"""PA#1 API routes — OWF + PRG."""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class EvalOWFRequest(BaseModel):
    x: int
    bits: int = 64


class GeneratePRGRequest(BaseModel):
    seed: int
    output_bits: int = 100
    owf_bits: int = 64


class StatTestRequest(BaseModel):
    bits: list[int]


@router.post("/evaluate-owf")
def evaluate_owf(req: EvalOWFRequest):
    """Evaluate the DLP OWF at x."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from crypto.pa01_owf_prg import DLP_OWF
    owf = DLP_OWF(bits=req.bits)
    y = owf.evaluate(req.x)
    params = owf.get_params()
    return {"y": y, "p": params["p"], "q": params["q"], "g": params["g"]}


@router.post("/generate-prg")
def generate_prg(req: GeneratePRGRequest):
    """Generate pseudorandom bits using the PRG."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from crypto.pa01_owf_prg import DLP_OWF, PRG
    owf = DLP_OWF(bits=req.owf_bits)
    prg = PRG(owf)
    bits = prg.generate(req.seed, req.output_bits)
    return {"bits": bits, "output_length": len(bits)}


@router.post("/run-statistical-tests")
def run_statistical_tests(req: StatTestRequest):
    """Run NIST SP 800-22 subset tests on the provided bits."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from crypto.pa01_owf_prg import StatisticalTests
    bits = req.bits
    freq_pass, freq_p = StatisticalTests.frequency_monobit(bits)
    runs_pass, runs_p = StatisticalTests.runs_test(bits)
    serial_pass, serial_p = StatisticalTests.serial_test(bits)
    return {
        "frequency_monobit": {"pass": freq_pass, "p_value": freq_p},
        "runs_test": {"pass": runs_pass, "p_value": runs_p},
        "serial_test": {"pass": serial_pass, "p_value": serial_p},
    }
