"""Check replaced Agent dependency APIs, Pillow codecs and real FastEmbed inference."""
import importlib.metadata
import io
import json
import sys

from PIL import Image
import numpy as np
from fastembed import TextEmbedding

assert importlib.metadata.version('fastembed') == '0.9.1'
assert importlib.metadata.version('Pillow') == '13.0.0'
for format in ('PNG', 'JPEG', 'WEBP'):
    stream = io.BytesIO()
    original = Image.new('RGB', (32, 32), (12, 34, 56))
    original.save(stream, format=format)
    stream.seek(0)
    with Image.open(stream) as image:
        assert image.resize((16, 16)).convert('RGB').size == (16, 16)
offline = sys.argv[1] == 'offline'
model = TextEmbedding(model_name='BAAI/bge-small-en-v1.5', cache_dir='/tmp/fastembed',
                      local_files_only=offline, threads=1)
embeddings = np.array(list(model.embed(['safe deployment', 'safe deployment', 'orange fruit'])))
assert embeddings.shape == (3, 384)
assert np.isfinite(embeddings).all()
assert np.allclose(embeddings[0], embeddings[1])
assert not np.allclose(embeddings[0], embeddings[2])
print(json.dumps({'pillow_codecs': 'pass', 'fastembed': '0.9.1', 'pillow': '13.0.0',
                  'text_inference': 'pass', 'offline': offline, 'vector_dimensions': 384}))
