FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir -e .

EXPOSE 8000
CMD ["uvicorn", "summer_puppy.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
