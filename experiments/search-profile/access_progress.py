#!/usr/bin/env python3
"""Read small Host stdout logs; never contact the Guest or open event payloads.

This is a progress aid, not evidence verification or a benchmark report.  In
particular, 128 logged completions do not imply post-source checks, successful
collector replay, or valid final comparison results.
"""
import argparse
from collections import Counter
import json
import math
from pathlib import Path

import access_search


MAX_LOG_BYTES = 16 * 1024 ** 2


def read_log(path):
    path = Path(path)
    if path.stat().st_size > MAX_LOG_BYTES:
        raise ValueError('small progress log exceeds 16 MiB bound')
    return path.read_text(encoding='utf-8')


def progress(text, plans, first=0):
    completed, started, issues, health = [], None, [], Counter()
    partial_tail = False
    lines = text.splitlines(keepends=True)
    for line_number, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except ValueError:
            if line_number == len(lines) and not line.endswith(('\n', '\r')):
                partial_tail = True
            else:
                issues.append('INVALID_JSON_LOG_LINE:' + str(line_number))
            continue
        if not isinstance(row, dict):
            issues.append('NON_OBJECT_LOG_LINE:' + str(line_number))
            continue
        if 'trial_index' in row:
            index = row['trial_index']
            if (type(index) is not int or index != first + len(completed)
                    or not 0 <= index < len(plans) or started is not None
                    or any(row.get(key) != value for key, value in plans[index].items())):
                issues.append('NON_PREFIX_OR_CHANGED_TRIAL_START:' + str(index))
                continue
            started = index
        elif 'completed' in row:
            index, seconds = row['completed'], row.get('wall_seconds')
            if (type(index) is not int or started != index or index != first + len(completed)
                    or type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0):
                issues.append('NON_PREFIX_OR_INVALID_TRIAL_COMPLETION:' + str(index))
                continue
            expected = 'COMPLETE_FOR_SELECTED_HOOKS' if plans[index]['file_access_mode'] == 'access' else 'NOT_ENABLED'
            state = row.get('file_access_health')
            if state != expected:
                issues.append('DECLARED_CAPTURE_HEALTH_NOT_COMPLETE:' + str(index) + ':' + str(state))
            health[str(state)] += 1
            completed.append({'index': index, 'seconds': seconds, 'file_access_health': state})
            started = None
    return {'completed': completed, 'in_progress_logical_index': started,
        'declared_health_counts': dict(health), 'ignored_partial_last_line': partial_tail, 'issues': issues}


def report(original, original_stdout, continuation_stdout, elapsed_seconds=None):
    plans = access_search.schedule(5, original['seed'])
    if (original.get('schedule') != plans or original.get('status') != 'FAILED'
            or len(original.get('campaigns', [])) != 54):
        raise ValueError('this pause campaign requires exact FAILED original prefix of 54')
    old = progress(original_stdout, plans)
    new = progress(continuation_stdout, plans, 32)
    issues = ['ORIGINAL_LOG:' + issue for issue in old['issues']] + ['CONTINUATION_LOG:' + issue for issue in new['issues']]
    if len(old['completed']) != 54:
        issues.append('ORIGINAL_LOG_DOES_NOT_MATCH_PRESERVED_54_COMPLETIONS')
    selected_count = 32 + len(new['completed'])
    if issues:
        status = 'PROGRESS_LOG_REQUIRES_INSPECTION'
    elif len(new['completed']) == 128:
        status = 'LOGGED_ALL_CONTINUATION_TRIALS_NOT_VERIFIED'
    else:
        status = 'PARTIAL_LOG_PROGRESS_NOT_FINAL_VERIFICATION'
    old_kept = [row for row in old['completed'] if row['index'] < 32]
    selected = old_kept + new['completed']
    counts = Counter((plans[row['index']]['block'], plans[row['index']]['file_access_mode']) for row in selected)
    result = {'schema_version': 1, 'status': status, 'selected_completed_log_count': selected_count,
        'selected_total': 160, 'retained_original_count': 32, 'excluded_original_completed_count': 22,
        'continuation_completed_log_count': len(new['completed']), 'continuation_total': 128,
        'continuation_remaining_log_count': 128 - len(new['completed']),
        'current_logical_index': new['in_progress_logical_index'],
        'current_condition': plans[new['in_progress_logical_index']] if new['in_progress_logical_index'] is not None else None,
        'next_expected_logical_index': 32 + len(new['completed']) if len(new['completed']) < 128 else None,
        'selected_declared_health_counts': dict(Counter(row['file_access_health'] for row in selected)),
        'completed_by_block_and_mode': [{'block': block, 'mode': mode, 'count': count}
            for (block, mode), count in sorted(counts.items())],
        'ignored_partial_last_line': new['ignored_partial_last_line'], 'issues': issues,
        'estimated_outer_schedule_seconds_remaining': None,
        'historical_seconds_per_32_trial_block': None,
        'scope': 'HOST_STDOUT_ONLY_NO_GUEST_CONTACT_NO_RAW_EVENT_READ_NO_FINAL_VALIDATION',
        'limits': ['Logged completion is not successful final post-source rehash or offline evidence replay.',
            'Historical outer cadence includes cache preparation and collector finalization, not just task wall time.',
            'Any duration estimate excludes final source/inode checks, export, offline conversion and verifier.',
            'An idle or unchanged log does not establish a stuck process or failure.']}
    if elapsed_seconds is not None:
        if type(elapsed_seconds) not in (int, float) or not math.isfinite(elapsed_seconds) or elapsed_seconds <= 0:
            raise ValueError('explicit positive historical outer elapsed seconds required')
        per_trial = elapsed_seconds / 54
        result['historical_seconds_per_32_trial_block'] = per_trial * 32
        result['estimated_outer_schedule_seconds_remaining'] = per_trial * (128 - len(new['completed']))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original-matrix', required=True, type=Path)
    parser.add_argument('--original-stdout', required=True, type=Path)
    parser.add_argument('--continuation-stdout', required=True, type=Path)
    parser.add_argument('--historical-elapsed-seconds', type=float,
        help='explicit approximate original start to last completed log elapsed; never inferred as task timing')
    args = parser.parse_args()
    original = json.loads(read_log(args.original_matrix))
    result = report(original, read_log(args.original_stdout), read_log(args.continuation_stdout), args.historical_elapsed_seconds)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result['issues'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
