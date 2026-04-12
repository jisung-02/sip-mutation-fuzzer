---
name: review-and-fix
description: 현재 작업 중인 코드 변경사항을 리뷰하고 타당한 이슈만 수정한다. "리뷰해줘", "리뷰하고 수정", "review" 등을 요청할 때 사용한다.
---

# 코드 리뷰 및 선택적 수정

현재 uncommitted 변경사항을 체계적으로 리뷰하고, 타당한 이슈만 수정한다.

## 리뷰 절차

### 1단계: 변경 범위 파악

```bash
git status --short
git diff --stat
```

### 2단계: Self-review 실행

Explore 에이전트를 사용해서 다음을 점검한다:

1. **정확성 버그**: 레이스 컨디션, 로직 오류, 엣지 케이스
2. **누락된 전파**: 새 타입/값이 모든 관련 위치에 전파되었는지
   - Verdict 추가 → `CampaignSummary`, `_update_summary`, `find_checkpoint`
   - Config 필드 추가 → CLI 옵션, validator, 테스트
3. **성능 문제**: 불필요한 반복 호출, subprocess 남용
4. **테스트 커버리지 갭**: 테스트되지 않은 중요 경로

### 3단계: 이슈 분류 및 판단

발견된 이슈를 테이블로 정리한다:

```
| # | 이슈 | 심각도 | 조치 |
|---|------|--------|------|
| 1 | [설명] | CRITICAL/HIGH/Medium/Low | 수정/스킵 |
```

**수정 기준**:
- CRITICAL/HIGH: 데이터 손실, 무한 루프, 레이스 컨디션 → 반드시 수정
- Medium: 성능, 타입 안전 → 코드 복잡도 증가 대비 판단
- Low: 스타일, 문서 → 스킵 (기존 설계와 충돌하지 않으면)

**스킵 기준**:
- 기존 설계 의도와 다른 방향의 제안
- 범위를 벗어나는 리팩터링
- 구현 복잡도 대비 가치가 낮은 개선

### 4단계: 수정 적용

타당한 이슈만 수정하고, 테스트를 실행한다.

### 5단계: 결과 보고

```
### 발견된 이슈

| # | 이슈 | 심각도 | 조치 |
|---|------|--------|------|
| 1 | ... | ... | 수정 |
| 2 | ... | ... | 스킵 (이유) |

### 수정 N: [이슈 제목]
- [구체적 변경 내용]

### 테스트 결과
- X passed, Y failed (pre-existing)
```

## Codex 리뷰 병행 (선택)

사용자가 "codex로도" 또는 "codex 리뷰"를 요청하면:

```bash
node "/Users/chaejisung/.claude/plugins/cache/openai-codex/codex/1.0.2/scripts/codex-companion.mjs" review
```

Codex 결과가 나오면 self-review 결과와 교차 검증하여 타당한 것만 수정한다.
