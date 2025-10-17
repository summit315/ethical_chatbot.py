#!/usr/bin/env python3
"""
ethical_chatbot.py

Terminal chatbot that:
 - understands Bangla and English (auto-detect)
 - does web searches (DuckDuckGo + simple scraping fallback)
 - summarizes results and replies in the user's language
 - blocks and refuses dangerous/illicit "how-to exploit" requests and gives safe alternatives

Dependencies:
 pip install requests beautifulsoup4 langdetect
"""

import requests
import time
import html
from bs4 import BeautifulSoup
from langdetect import detect, DetectorFactory
DetectorFactory.seed = 0  # deterministic language detection

# --- CONFIG ---
# Optional: If you have SerpAPI or Bing Search API, you can plug them in for better results.
SERPAPI_KEY = None  # "YOUR_SERPAPI_KEY"
BING_API_KEY = None  # "YOUR_AZURE_BING_KEY"

DUCKDUCKGO_INSTANT_ANSWER = "https://api.duckduckgo.com/?q={q}&format=json&no_html=1&skip_disambig=1"
DUCKDUCKGO_HTML = "https://html.duckduckgo.com/html/"

LIBRETRANSLATE_URL = "https://libretranslate.com/translate"  # free public endpoint (small usage only)

# Safety rules: refuse/avoid step-by-step illicit actions
DANGEROUS_PATTERNS = [
    "exploit", "zero day", "zero-day", "payload", "reverse shell", "meterpreter",
    "crack password", "bypass firewall", "bypass authentication", "sql injection payload",
    "ddos script", "how to hack", "steal", "keylogger", "malware", "ransomware",
    "dump creds", "bruteforce", "credential stuffing", "exploit kit", "rootkit",
    "escalate privileges", "privilege escalation exploit", "unauthorized access"
]
# also look for short Bangla forms:
DANGEROUS_PATTERNS_BN = [
    "hack kora", "password bhangte", "crack kora", "ddos", "malware", "keylogger",
    "pawa na", "bypass kora", "unauthorized", "churi"
]

# --- Helpers ---


def detect_language(text: str) -> str:
    try:
        lang = detect(text)
        if lang.startswith("bn"):
            return "bn"
        return "en"
    except Exception:
        return "en"


def translate(text: str, source: str, target: str) -> str:
    """Use LibreTranslate for small translations. If the service fails, return original."""
    if source == target:
        return text
    try:
        payload = {"q": text, "source": source, "target": target, "format": "text"}
        resp = requests.post(LIBRETRANSLATE_URL, data=payload, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("translatedText", text)
    except Exception:
        pass
    return text


def contains_dangerous_terms(text: str) -> bool:
    t = text.lower()
    for p in DANGEROUS_PATTERNS + DANGEROUS_PATTERNS_BN:
        if p in t:
            return True
    return False


def duckduckgo_instant(q: str):
    """Try DuckDuckGo instant answer JSON first."""
    try:
        url = DUCKDUCKGO_INSTANT_ANSWER.format(q=requests.utils.quote(q))
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            data = r.json()
            abstract = data.get("AbstractText", "") or data.get("Answer", "")
            related = data.get("RelatedTopics", [])
            snippets = []
            if abstract:
                snippets.append(abstract)
            # collect small related snippets
            for item in related[:5]:
                if isinstance(item, dict):
                    text = item.get("Text") or item.get("Result")
                    if text:
                        snippets.append(BeautifulSoup(text, "html.parser").get_text())
            return snippets
    except Exception:
        pass
    return []


def duckduckgo_scrape(q: str, max_results=5):
    """Simple DuckDuckGo HTML scraping fallback to get result snippets (no API key)."""
    try:
        resp = requests.post(DUCKDUCKGO_HTML, data={"q": q}, timeout=8)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            results = []
            for a in soup.select(".result__snippet")[:max_results]:
                text = a.get_text(separator=" ", strip=True)
                if text:
                    results.append(text)
            # fallback: .result__a titles
            if not results:
                for r in soup.select(".result__a")[:max_results]:
                    t = r.get_text(separator=" ", strip=True)
                    if t:
                        results.append(t)
            return results
    except Exception:
        pass
    return []


def web_search(q: str, max_results=5):
    """Try multiple strategies: SerpAPI (if key), Bing (if key), then DuckDuckGo instant, then scrape."""
    snippets = []
    # 1) SerpAPI (optional)
    if SERPAPI_KEY:
        try:
            params = {"q": q, "api_key": SERPAPI_KEY, "num": max_results}
            r = requests.get("https://serpapi.com/search.json", params=params, timeout=8)
            j = r.json()
            for o in j.get("organic_results", [])[:max_results]:
                snippet = o.get("snippet") or o.get("title")
                if snippet:
                    snippets.append(snippet)
            if snippets:
                return snippets
        except Exception:
            pass

    # 2) Bing (optional)
    if BING_API_KEY:
        try:
            headers = {"Ocp-Apim-Subscription-Key": BING_API_KEY}
            params = {"q": q, "count": max_results}
            r = requests.get("https://api.bing.microsoft.com/v7.0/search", params=params, headers=headers, timeout=8)
            j = r.json()
            webPages = j.get("webPages", {}).get("value", [])
            for w in webPages[:max_results]:
                snippets.append(w.get("snippet") or w.get("name"))
            if snippets:
                return snippets
        except Exception:
            pass

    # 3) DuckDuckGo instant
    snippets = duckduckgo_instant(q)
    if snippets:
        return snippets

    # 4) scrape
    snippets = duckduckgo_scrape(q, max_results=max_results)
    return snippets


def summarize_snippets(snippets):
    """Very lightweight summarizer: join top snippets, deduplicate, trim length."""
    if not snippets:
        return ""
    seen = set()
    out = []
    for s in snippets:
        s_clean = " ".join(s.split())
        if s_clean not in seen:
            seen.add(s_clean)
            out.append(s_clean)
    joined = " ".join(out)
    # shorten to ~600 chars
    if len(joined) > 600:
        return joined[:590].rsplit(" ", 1)[0] + "..."
    return joined


def safe_response_for_refusal(lang):
    if lang == "bn":
        return ("Ami dukkhoito, kintu ami kono oshamorthok ba apradhik/kibhabe hacking kora jay "
                "sei dhoroner step-by-step instruction dite pari na. "
                "Apni jodi ethical hacking (sikha, responsible testing, vulnerability reporting) niye "
                "shohoj, legal, ebong safe tottho chan, ami shei dhoroner high-level guidance, "
                "resource list, ebong legal frameworks dite pari.")
    else:
        return ("Sorry — I can't provide step-by-step instructions for hacking, exploiting systems, "
                "or any malicious actions. If you want ethical hacking knowledge (theory, defensive methods, "
                "how to get started legally, reporting vulnerabilities), I can provide high-level guidance and safe resources.")


def answer_question(question: str, user_lang: str):
    """
    Main routine:
    - detect dangerous requests -> refuse with safe response
    - search web for snippets
    - summarize and translate to user's language
    """
    # Safety check
    if contains_dangerous_terms(question):
        return safe_response_for_refusal(user_lang)

    # Choose search language: if user in Bangla, search english + bangla variants
    q_for_search = question
    if user_lang == "bn":
        # translate to english to improve search coverage (best-effort)
        q_en = translate(question, "bn", "en")
        q_for_search = f"{q_en} (Bangla: {question})"
    else:
        q_for_search = question

    snippets = web_search(q_for_search, max_results=6)
    if not snippets:
        # fallback: return safe high level tips
        fallback = ("I couldn't find direct search results for that request. "
                    "Try rephrasing, or ask for general theory/resources.")
        return translate(fallback, "en", "bn") if user_lang == "bn" else fallback

    summary_en = summarize_snippets(snippets)
    # If user language is Bangla, translate the summary to Bangla
    if user_lang == "bn":
        summary_bn = translate(summary_en, "en", "bn")
        # also include short list of sources (we didn't record full urls in this simple version)
        return summary_bn + "\n\n(ori English summary: " + (summary_en[:400] + ("..." if len(summary_en) > 400 else "")) + ")"
    else:
        return summary_en


# --- CLI loop ---
def run_cli():
    print("=== Ethical Chatbot (Bangla/English) ===")
    print("Type 'exit' to quit. Ask about ethical hacking topics (high-level).")
    print("NOTE: I will refuse step-by-step malicious instructions.")
    while True:
        try:
            q = input("\nYou: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            break
        if not q:
            continue
        if q.lower() in ("exit", "quit"):
            print("Bye.")
            break

        user_lang = detect_language(q)
        # handle quick safety pattern detection
        if contains_dangerous_terms(q):
            reply = safe_response_for_refusal(user_lang)
            print("\nBot:", reply)
            continue

        print("Bot: searching the web for relevant, reliable info... (this may take a few seconds)")
        answer = answer_question(q, user_lang)
        print("\nBot:", answer)


if __name__ == "__main__":
    run_cli()
