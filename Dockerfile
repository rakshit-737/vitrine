FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/rakshit-737/vitrine"
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY vitrine ./vitrine
RUN pip install --no-cache-dir ".[ml,api]" && useradd -r -u 10001 vitrine
USER vitrine
EXPOSE 8000
# Mount a trained model at /models/vitrine_xgb.json; without it the synthetic demo model is used.
CMD ["sh", "-c", "if [ -f /models/vitrine_xgb.json ]; then exec vitrine serve --host 0.0.0.0 --model /models/vitrine_xgb.json; else exec vitrine serve --host 0.0.0.0; fi"]
