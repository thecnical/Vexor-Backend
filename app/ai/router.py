"""
Vexor AI Router — All AI endpoints
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.ai.orchestrator import AIOrchestrator
from app.auth.dependencies import get_current_user

router = APIRouter()
orchestrator = AIOrchestrator()


class AnalyzeRequest(BaseModel):
    request: str = ""
    response: str = ""
    vulnerability: str = ""


class ExplainRequest(BaseModel):
    content: str


class SuggestRequest(BaseModel):
    context: str


class PayloadRequest(BaseModel):
    target: str = ""
    payload_type: str = "general"
    count: int = 20


class FilterRequest(BaseModel):
    findings: str


class ReportRequest(BaseModel):
    findings: str


@router.post("/analyze")
async def analyze(req: AnalyzeRequest, user=Depends(get_current_user)):
    result = await orchestrator.analyze_vulnerability(
        request=req.request,
        response=req.response,
        vuln=req.vulnerability,
    )
    return {"result": result}


@router.post("/explain")
async def explain(req: ExplainRequest, user=Depends(get_current_user)):
    result = await orchestrator.explain_content(content=req.content)
    return {"result": result}


@router.post("/suggest")
async def suggest(req: SuggestRequest, user=Depends(get_current_user)):
    result = await orchestrator.suggest_attack(context=req.context)
    return {"result": result}


@router.post("/payload")
async def generate_payload(req: PayloadRequest, user=Depends(get_current_user)):
    payloads = await orchestrator.generate_payloads(
        target=req.target,
        payload_type=req.payload_type,
        count=req.count,
    )
    return {"payloads": payloads}


@router.post("/filter")
async def filter_fps(req: FilterRequest, user=Depends(get_current_user)):
    result = await orchestrator.filter_false_positives(findings=req.findings)
    return {"result": result}


@router.post("/report")
async def write_report(req: ReportRequest, user=Depends(get_current_user)):
    result = await orchestrator.write_report_section(findings=req.findings)
    return {"result": result}
