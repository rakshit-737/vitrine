FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
LABEL org.opencontainers.image.source="https://github.com/rakshit-737/vitrine"
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY vitrine ./vitrine
# xgboost-cpu: same `xgboost` module without the 300 MB NCCL GPU wheel this CPU image never uses.
RUN pip install --no-cache-dir --upgrade "pip>=26.2" \
 && pip install --no-cache-dir ".[api]" "scikit-learn>=1.3" "xgboost-cpu>=2.1" \
 && useradd -r -u 10001 vitrine
USER vitrine
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/health').status != 200)"
# Publish on localhost only: docker run -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/vitrine
# Mount a trained model at /models/vitrine_xgb.json; without it the synthetic demo model is used.
CMD ["sh", "-c", "if [ -f /models/vitrine_xgb.json ]; then exec vitrine serve --host 0.0.0.0 --model /models/vitrine_xgb.json; else exec vitrine serve --host 0.0.0.0; fi"]
