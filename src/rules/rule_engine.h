#pragma once
/*
 * rule_engine.h - EDR 탐지 룰 엔진
 *
 * 설계 원칙:
 *   각 이벤트 구조체(process_event, file_event, net_event)를 받아
 *   매칭된 룰 목록을 반환하는 순수 함수(stateless) 인터페이스.
 *
 *   룰은 rule_engine.cpp 의 정적 테이블에 정의된다.
 *   런타임에 파일에서 로드하는 기능은 마일스톤 4+ 에서 추가.
 */
#include <vector>
#include "common.h"

struct RuleMatch {
    const char *id;        /* "R-001" 형식의 고유 식별자     */
    const char *name;      /* 사람이 읽는 룰 이름             */
    const char *severity;  /* "critical"|"high"|"medium"|"low" */
};

/* 이벤트 타입별 룰 매칭 */
std::vector<RuleMatch> match_rules(const process_event &e);
std::vector<RuleMatch> match_rules(const file_event &e);
std::vector<RuleMatch> match_rules(const net_event &e);

/*
 * 프로세스 트리 컨텍스트 포함 버전.
 * parent_comm: 부모 프로세스의 comm (nullptr/빈 문자열이면 기본 버전과 동일).
 * 기본 match_rules(e) 결과에 R-011/R-012 를 추가 검사한다.
 */
std::vector<RuleMatch> match_rules(const process_event &e, const char *parent_comm);

/* severity 문자열 → ANSI 색상 코드 반환 */
const char *severity_color(const char *severity);
