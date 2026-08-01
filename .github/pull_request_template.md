## Purpose

<!-- What assurance or user outcome changes? -->

## Traceability

- Criticality: IC-1 / IC-2 / IC-3 / IC-4
- Requirements:
- Hazards:
- Threats:
- Integris Proposal (if required):

## Risk and failure behavior

- Threats/hazards mitigated:
- Residual risk or new assumptions:
- Safe behavior on error, interruption, or exhaustion:
- Rollback/retirement impact:

## Verification evidence

- Methods and acceptance criteria:
- Commands/results:
- Evidence records and artifact digests:
- Platforms/filesystems exercised:

## Review roles

- [ ] Author identified
- [ ] Technical reviewer assigned
- [ ] Security reviewer assigned when IC-1/IC-3 or trust boundary changes
- [ ] Assurance owner assigned for IC-1/IC-2 and release evidence
- [ ] Author is not the sole IC-1 approver

## Checklist

- [ ] Machine-readable records and generated traceability are current
- [ ] Negative and fault cases are tested in proportion to criticality
- [ ] No secret, content, personal data, or sensitive path enters logs/fixtures
- [ ] Documentation, migration, recovery, and retirement remain coherent
- [ ] `make verify` passes
