"""Run inside a disposable protected Guardrail container with test-only ACLs."""
import asyncio
import json
import os
import urllib.parse
import urllib.request
import uuid

from approval_store import consume
from rate_limiter import _check_limit, close_redis_pool, initialize_redis_pool
from redis_config import load_redis_connection_settings
from rule_store import KEY_INPUT_INJECTION, RuleStore
from session_store import SessionStore
from tool_models import ToolRequest
import redis.asyncio as redis_async
from redis.exceptions import NoPermissionError


def request(path, data, *, form=False, token=None):
    payload = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
    headers={'Content-Type':'application/x-www-form-urlencoded' if form else 'application/json'}
    if token: headers['Authorization']='Bearer '+token
    with urllib.request.urlopen(urllib.request.Request('http://localhost:8000'+path,data=payload,headers=headers),timeout=30) as result:
        if result.status != 200: raise ValueError
        return json.load(result)


async def main():
    run_id=uuid.uuid4().hex
    if not await initialize_redis_pool(): raise ValueError
    allowed, remaining, _ = await _check_limit('ci:rate:'+run_id, limit=2, window=60)
    if not allowed or remaining != 1: raise ValueError
    allowed, remaining, _ = await _check_limit('ci:rate:'+run_id, limit=2, window=60)
    if not allowed or remaining != 0: raise ValueError
    allowed, _, _ = await _check_limit('ci:rate:'+run_id, limit=2, window=60)
    if allowed: raise ValueError
    connection=redis_async.Redis(**load_redis_connection_settings().client_kwargs())
    try:
        try: await connection.execute_command('ACL','USERS')
        except NoPermissionError: pass
        else: raise ValueError
        history=SessionStore(connection)
        await history.append('ci:'+run_id,'user','fixture')
        stored=await history.get_history('ci:'+run_id)
        if len(stored) != 1 or stored[0].get('content') != 'fixture': raise ValueError
        await history.clear('ci:'+run_id)
        if await history.get_history('ci:'+run_id): raise ValueError
        rules=RuleStore(connection)
        pattern='ci'+run_id
        if not await rules.add_rule(KEY_INPUT_INJECTION,pattern): raise ValueError
        if pattern not in await rules.list_rules(KEY_INPUT_INJECTION): raise ValueError
        if not await rules.remove_rule(KEY_INPUT_INJECTION,pattern): raise ValueError
        if not await rules.add_pii_rule('CI'+run_id[:16],pattern): raise ValueError
        if (await rules.list_pii_rules()).get('CI'+run_id[:16]) != pattern: raise ValueError
        if not await rules.remove_pii_rule('CI'+run_id[:16]): raise ValueError
    finally:
        await connection.aclose()
        await close_redis_pool()
    login=request('/auth/token',{'username':'admin','password':os.environ['CI_ADMIN_PASSWORD']},form=True)
    request_data={'tool_name':'ci-tool','arguments':{'id':run_id},'end_user_id':'ci-user',
                  'ticket_id':'ci-ticket','ttl_seconds':60}
    approval=request('/tools/approvals',request_data,token=login['access_token'])
    tool=ToolRequest(tool_name='ci-tool',arguments={'id':run_id},end_user_id='ci-user')
    if not consume(approval['token'],tool) or consume(approval['token'],tool): raise ValueError
    print('REDIS_ACL_PRODUCT_PROBE_PASS')


asyncio.run(main())
