#pragma once
/*
 * json_fmt.h - 이벤트 구조체 → JSON 문자열 변환
 *
 * 외부 라이브러리 없이 직접 구현한 경량 JSON 직렬화.
 * 출력 형식: NDJSON (Newline-Delimited JSON) — 한 이벤트 = 한 줄.
 *
 * 선택 이유:
 *   nlohmann/json, rapidjson 등을 쓰면 편하지만,
 *   직접 구현하면 JSON 구조와 이스케이핑 규칙을 저수준에서 이해할 수 있다.
 */
#include <string>
#include <vector>
#include "common.h"
#include "rules/rule_engine.h"

/* JSON 문자열 이스케이프: '"' → '\"', '\' → '\\', 제어문자 → \uXXXX */
std::string json_esc(const char *s);

/* 이벤트 → JSON 한 줄 (후행 개행 없음) */
std::string to_json(const process_event &e, const std::vector<RuleMatch> &hits);
std::string to_json(const file_event    &e, const std::vector<RuleMatch> &hits);
std::string to_json(const net_event     &e, const std::vector<RuleMatch> &hits);
std::string to_json(const ptrace_event  &e, const std::vector<RuleMatch> &hits);
std::string to_json(const memory_event  &e, const std::vector<RuleMatch> &hits);
std::string to_json(const memfd_event   &e, const std::vector<RuleMatch> &hits);
std::string to_json(const dns_event     &e, const std::vector<RuleMatch> &hits);
std::string to_json(const ns_event      &e, const std::vector<RuleMatch> &hits);
