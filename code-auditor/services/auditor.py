"""
Auditor service — Gemini AI integration for code analysis.
Constructs prompts, calls the Gemini API, and parses structured JSON responses.
"""

import json
import os
import re
from pathlib import Path
from dotenv import load_dotenv
from google import genai
from google.genai import types

# Initialize the client (will be configured in main.py after loading .env)
_client = None


def get_client() -> genai.Client:
    """Get or create the Gemini client."""
    global _client
    if _client is None:
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key or api_key == "your_api_key_here":
            env_file = Path(__file__).resolve().parent.parent / ".env"
            if env_file.exists():
                load_dotenv(dotenv_path=env_file, override=True)
                api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key or api_key == "your_api_key_here":
            raise ValueError(
                "GEMINI_API_KEY is not set. Please add it to your .env file."
            )
        _client = genai.Client(api_key=api_key)
    return _client


SYSTEM_PROMPT = """You are a senior code reviewer and security auditor with 20+ years of experience.
Analyze the provided code and return a structured JSON audit report.

You MUST return ONLY valid JSON (no markdown fences, no extra text) matching this exact schema:

{
  "language": "<detected programming language>",
  "summary": "<brief overview of what the code does, 1-3 sentences>",
  "findings": [
    {
      "severity": "critical | high | medium | low | info",
      "category": "security | accessibility | performance | best-practice | maintainability | error-handling",
      "title": "<short descriptive title>",
      "description": "<detailed explanation of the issue>",
      "line_range": [<start_line>, <end_line>],
      "suggestion": "<how to fix it>",
      "code_snippet": "<suggested fix code>"
    }
  ],
  "scores": {
    "security": <0-100>,
    "accessibility": <0-100>,
    "performance": <0-100>,
    "maintainability": <0-100>,
    "overall": <0-100>
  },
  "topics_detected": ["<topic1>", "<topic2>"],
  "complexity_level": "beginner | intermediate | advanced"
}

Rules:
- Be thorough but fair. Don't invent issues that don't exist.
- Scores should reflect the actual quality. Perfect code can score 95-100.
- Always include at least one finding, even if it's just an "info" level suggestion.
- line_range should reference actual line numbers in the provided code.
- For the "overall" score, weight security highest, then maintainability, then performance.
- Detect topics like: authentication, database queries, file I/O, networking, concurrency, etc.
- Return ONLY the JSON object, nothing else.
"""


REQUIREMENTS_SYSTEM_PROMPT = """You are a senior code reviewer, security auditor, and standards compliance specialist with 20+ years of experience.
Analyze the provided code against BOTH general best practices AND the user's specific requirements.

You MUST return ONLY valid JSON (no markdown fences, no extra text) matching this exact schema:

{
  "language": "<detected programming language>",
  "summary": "<brief overview of what the code does, 1-3 sentences>",
  "findings": [
    {
      "severity": "critical | high | medium | low | info",
      "category": "security | accessibility | performance | best-practice | maintainability | error-handling | standards-compliance",
      "title": "<short descriptive title>",
      "description": "<detailed explanation of the issue>",
      "line_range": [<start_line>, <end_line>],
      "suggestion": "<how to fix it>",
      "code_snippet": "<suggested fix code>"
    }
  ],
  "scores": {
    "security": <0-100>,
    "accessibility": <0-100>,
    "performance": <0-100>,
    "maintainability": <0-100>,
    "overall": <0-100>,
    "standards": <0-100>
  },
  "requirements_checklist": [
    {
      "requirement": "<the specific requirement being checked>",
      "status": "pass | fail | partial",
      "details": "<brief explanation of compliance status>",
      "recommendation": "<specific action to fix if fail/partial, or empty string if pass>"
    }
  ],
  "topics_detected": ["<topic1>", "<topic2>"],
  "complexity_level": "beginner | intermediate | advanced",
  "standards_summary": "<2-3 sentence summary of how well the code meets the specified requirements>"
}

Rules:
- Be thorough but fair. Don't invent issues that don't exist.
- Scores should reflect actual quality. Perfect code can score 95-100.
- Always include at least one finding, even if it's just an "info" level suggestion.
- line_range should reference actual line numbers in the provided code.
- For the "overall" score, weight security highest, then maintainability, then performance.
- For the "standards" score (0-100): 100 = fully compliant, 0 = completely non-compliant. Weight it by severity of the requirement type.
- In requirements_checklist, include ALL the requirements the user specified, one entry each.
- status must be exactly "pass", "fail", or "partial" (lowercase).
- Detect topics like: authentication, database queries, file I/O, networking, concurrency, etc.
- Return ONLY the JSON object, nothing else.
"""


async def audit_code(code: str, filename: str | None = None, language_hint: str | None = None) -> dict:
    """
    Send code to Gemini for audit analysis.
    
    Args:
        code: The source code to audit
        filename: Optional filename for context
        language_hint: Optional language hint
    
    Returns:
        Parsed audit result dictionary
    """
    client = get_client()

    # Build the user prompt
    user_parts = []
    if filename:
        user_parts.append(f"Filename: {filename}")
    if language_hint:
        user_parts.append(f"Language: {language_hint}")
    user_parts.append(f"Code to audit:\n```\n{code}\n```")
    user_prompt = "\n".join(user_parts)

    try:
        response = client.models.generate_content(
            model="gemini-3.8-flash",
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.3,
                max_output_tokens=8192,
            ),
        )

        response_text = response.text or ""
        raw_text = response_text.strip()
        if not raw_text:
            return _fallback_result(code, filename, language_hint, "Gemini returned an empty response")

        # Strip markdown code fences if present
        if raw_text.startswith("```"):
            # Remove opening fence (```json or ```)
            raw_text = re.sub(r'^```\w*\n?', '', raw_text)
            # Remove closing fence
            raw_text = re.sub(r'\n?```$', '', raw_text)
            raw_text = raw_text.strip()

        result = json.loads(raw_text)
        result["raw_text"] = response_text  # Keep original for debugging
        return _validate_and_normalize(result)

    except json.JSONDecodeError as e:
        # If Gemini didn't return valid JSON, return a fallback
        return _fallback_result(code, filename, language_hint, str(e))
    except Exception as e:
        raise RuntimeError(f"Gemini API error: {str(e)}") from e


async def audit_code_with_requirements(
    code: str,
    requirements: dict,
    filename: str | None = None,
    language_hint: str | None = None,
) -> dict:
    """
    Send code to Gemini for a requirements-aware standards audit.

    Args:
        code: The source code to audit
        requirements: Dict with keys: language_standard, security_framework,
                      complexity_threshold, naming_convention, additional_notes
        filename: Optional filename for context
        language_hint: Optional language hint

    Returns:
        Parsed audit result dictionary with requirements_checklist and standards score
    """
    client = get_client()

    # Build a rich requirements block
    req_lines = ["User-Specified Audit Requirements:"]
    if requirements.get("language_standard"):
        req_lines.append(f"  - Language/Style Standard: {requirements['language_standard']}")
    if requirements.get("security_framework"):
        req_lines.append(f"  - Security Framework: {requirements['security_framework']}")
    if requirements.get("complexity_threshold"):
        req_lines.append(f"  - Complexity Threshold: {requirements['complexity_threshold']}")
    if requirements.get("naming_convention"):
        req_lines.append(f"  - Naming Convention: {requirements['naming_convention']}")
    if requirements.get("additional_notes"):
        req_lines.append(f"  - Additional Requirements: {requirements['additional_notes']}")
    requirements_block = "\n".join(req_lines)

    # Build the user prompt
    user_parts = []
    if filename:
        user_parts.append(f"Filename: {filename}")
    if language_hint:
        user_parts.append(f"Language: {language_hint}")
    user_parts.append(requirements_block)
    user_parts.append(f"Code to audit:\n```\n{code}\n```")
    user_prompt = "\n".join(user_parts)

    try:
        response = client.models.generate_content(
            model="gemini-3.8-flash",
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=REQUIREMENTS_SYSTEM_PROMPT,
                temperature=0.3,
                max_output_tokens=8192,
            ),
        )

        response_text = response.text or ""
        raw_text = response_text.strip()
        if not raw_text:
            return _fallback_result_with_requirements(code, filename, language_hint, "Gemini returned an empty response")

        # Strip markdown code fences if present
        if raw_text.startswith("```"):
            raw_text = re.sub(r'^```\w*\n?', '', raw_text)
            raw_text = re.sub(r'\n?```$', '', raw_text)
            raw_text = raw_text.strip()

        result = json.loads(raw_text)
        result["raw_text"] = response_text
        return _validate_and_normalize_with_requirements(result)

    except json.JSONDecodeError as e:
        return _fallback_result_with_requirements(code, filename, language_hint, str(e))
    except Exception as e:
        raise RuntimeError(f"Gemini API error: {str(e)}") from e


def _validate_and_normalize(result: dict) -> dict:
    """Ensure the audit result has all required fields with correct types."""
    # Ensure scores exist and are integers 0-100
    scores = result.get("scores", {})
    for key in ("security", "accessibility", "performance", "maintainability", "overall"):
        val = scores.get(key, 50)
        scores[key] = max(0, min(100, int(val)))
    result["scores"] = scores

    # Ensure findings is a list
    if not isinstance(result.get("findings"), list):
        result["findings"] = []

    # Normalize each finding
    valid_severities = {"critical", "high", "medium", "low", "info"}
    valid_categories = {
        "security", "accessibility", "performance",
        "best-practice", "maintainability", "error-handling",
    }
    for finding in result["findings"]:
        if finding.get("severity") not in valid_severities:
            finding["severity"] = "info"
        if finding.get("category") not in valid_categories:
            finding["category"] = "best-practice"
        if not isinstance(finding.get("line_range"), list):
            finding["line_range"] = [None, None]
        finding.setdefault("title", "Untitled")
        finding.setdefault("description", "")
        finding.setdefault("suggestion", "")
        finding.setdefault("code_snippet", "")

    # Ensure other fields
    result.setdefault("language", "unknown")
    result.setdefault("summary", "No summary available.")
    result.setdefault("topics_detected", [])
    result.setdefault("complexity_level", "intermediate")

    if result["complexity_level"] not in ("beginner", "intermediate", "advanced"):
        result["complexity_level"] = "intermediate"

    return result


def _validate_and_normalize_with_requirements(result: dict) -> dict:
    """Validate and normalize a requirements-aware audit result."""
    result = _validate_and_normalize(result)

    # Validate standards score
    scores = result["scores"]
    if "standards" in scores:
        scores["standards"] = max(0, min(100, int(scores["standards"])))
    else:
        scores["standards"] = 50

    # Normalize requirements_checklist
    checklist = result.get("requirements_checklist", [])
    if not isinstance(checklist, list):
        checklist = []
    valid_statuses = {"pass", "fail", "partial"}
    for item in checklist:
        if item.get("status") not in valid_statuses:
            item["status"] = "partial"
        item.setdefault("requirement", "Unknown requirement")
        item.setdefault("details", "")
        item.setdefault("recommendation", "")
    result["requirements_checklist"] = checklist

    # Ensure standards_summary
    result.setdefault("standards_summary", "No standards summary available.")

    # Also allow "standards-compliance" category in findings
    for finding in result.get("findings", []):
        if finding.get("category") == "standards-compliance":
            pass  # valid category for requirements audits

    return result


def _fallback_result(code: str, filename: str | None, language_hint: str | None, error: str) -> dict:
    """Return a minimal result when Gemini response parsing fails."""
    lang = language_hint or "unknown"
    return {
        "language": lang,
        "summary": "The AI analysis could not produce a structured response. Please try again.",
        "findings": [
            {
                "severity": "info",
                "category": "best-practice",
                "title": "Analysis Incomplete",
                "description": f"The AI response could not be parsed: {error}",
                "line_range": [None, None],
                "suggestion": "Try submitting the code again or simplify the input.",
                "code_snippet": "",
            }
        ],
        "scores": {
            "security": 50,
            "accessibility": 50,
            "performance": 50,
            "maintainability": 50,
            "overall": 50,
        },
        "topics_detected": [],
        "complexity_level": "intermediate",
    }


def _fallback_result_with_requirements(
    code: str, filename: str | None, language_hint: str | None, error: str
) -> dict:
    """Return a minimal result when Gemini response parsing fails for requirements audit."""
    result = _fallback_result(code, filename, language_hint, error)
    result["scores"]["standards"] = 50
    result["requirements_checklist"] = []
    result["standards_summary"] = "The AI analysis could not produce a structured response. Please try again."
    return result
