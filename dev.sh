#!/bin/bash

docker compose up -d
uv run uvicorn app.main:app --reload