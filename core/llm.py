"""
core/llm.py — 4-Model LLM Stack

Models:
  orchestrator_think() → DeepSeek V3.1   (tool calling, orchestration, recon, reporting)
  vuln_think()         → Qwen3-235B      (deep reasoning loops for all vuln agents)
  gemini_analyze()     → Gemini 2.5 Pro  (large context: HTTP traffic, JS files)
  quick_think()        → Groq Llama 70B  (fast micro-tasks)

HOW TO SWAP A MODEL:
  Change the model constants in config.py — no need to edit this file.
  e.g. to use DeepSeek R1 for vulns: set MODEL_VULN = "deepseek-reasoner"
"""

import re
import time
import asyncio
from openai import OpenAI
from loguru import logger
import google.generativeai as genai
from tenacity import retry, stop_after_attempt, wait_exponential

import config

# ── Clients ────────────────────────────────────────────────────────
_deepseek_client = None
_groq_client     = None

def _get_deepseek():
    global _deepseek_client
    if not _deepseek_client:
        if not config.DEEPSEEK_API_KEY:
            raise ValueError("DEEPSEEK_API_KEY not set in .env")
        _deepseek_client = OpenAI(
            api_key=config.DEEPSEEK_API_KEY,
            base_url="https://api.deepseek.com"
        )
    return _deepseek_client

def _get_groq():
    global _groq_client
    if not _groq_client:
        if not config.GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not set in .env")
        _groq_client = OpenAI(
            api_key=config.GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1"
        )
    return _groq_client

def _init_gemini():
    if config.GEMINI_API_KEY:
        genai.configure(api_key=config.GEMINI_API_KEY)

_init_gemini()

# ── Groq rate limit semaphore ─────────────────────────────────────
_groq_semaphore = asyncio.Semaphore(config.GROQ_CONCURRENCY)

# ── Response Cleaner ──────────────────────────────────────────────
def _clean_response(text: str) -> str:
    """Strip thinking blocks and markdown fences from model output."""
    # Remove <think>...</think> blocks (DeepSeek R1 / Qwen3)
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    # Remove ```json ... ``` fences
    if '```json' in text:
        m = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if m:
            return m.group(1).strip()
    if '```' in text:
        m = re.search(r'```\s*(.*?)\s*```', text, re.DOTALL)
        if m:
            return m.group(1).strip()
    return text.strip()

# ── Public Functions ──────────────────────────────────────────────

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def orchestrator_think(messages: list, system: str, max_tokens: int = 3000) -> str:
    """
    DeepSeek V3.1 — used by: Orchestrator, Recon Agent, Crawler, Reporter.
    Best for tool calling and structured output.
    """
    try:
        client = _get_deepseek()
        response = client.chat.completions.create(
            model=config.MODEL_ORCHESTRATOR,
            messages=[{"role": "system", "content": system}] + messages,
            max_tokens=max_tokens,
        )
        return _clean_response(response.choices[0].message.content)
    except Exception as e:
        logger.warning(f"DeepSeek failed: {e} — falling back to Groq Llama")
        return quick_think(messages[-1]["content"] if messages else "")

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=3, max=15))
def vuln_think(messages: list, system: str, max_tokens: int = 4000) -> str:
    """
    Qwen3-235B on Groq — used by: ALL vuln agents + verifier.
    Best deep reasoning for methodology and bypass thinking.
    """
    try:
        client = _get_groq()
        response = client.chat.completions.create(
            model=config.MODEL_VULN,
            messages=[{"role": "system", "content": system}] + messages,
            max_tokens=max_tokens,
        )
        return _clean_response(response.choices[0].message.content)
    except Exception as e:
        logger.warning(f"Groq Qwen3 failed: {e} — falling back to DeepSeek")
        return orchestrator_think(messages, system, max_tokens)

def gemini_analyze(content: str, task: str, max_tokens: int = 4000) -> str:
    """
    Gemini 2.5 Pro — used by: Crawler (bulk HTTP analysis), JS Analyzer.
    Best for large context (1M tokens) — feed it 100s of requests at once.
    """
    if not config.GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set — using DeepSeek for analysis")
        return orchestrator_think(
            [{"role": "user", "content": f"{task}\n\n{content[:8000]}"}],
            "You are a security analyst."
        )
    try:
        model = genai.GenerativeModel(config.MODEL_GEMINI)
        response = model.generate_content(
            f"{task}\n\n{content}",
            generation_config=genai.GenerationConfig(max_output_tokens=max_tokens)
        )
        return response.text
    except Exception as e:
        logger.warning(f"Gemini failed: {e} — falling back to DeepSeek")
        return orchestrator_think(
            [{"role": "user", "content": f"{task}\n\n{content[:8000]}"}],
            "You are a security analyst."
        )

@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=5))
def quick_think(prompt: str, max_tokens: int = 500) -> str:
    """
    Groq Llama 3.3 70B — fast micro-tasks only.
    Use for: scope checks, keyword extraction, payload formatting.
    """
    try:
        client = _get_groq()
        response = client.chat.completions.create(
            model=config.MODEL_FAST,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
        )
        return _clean_response(response.choices[0].message.content)
    except Exception as e:
        logger.error(f"Quick think failed: {e}")
        return ""
