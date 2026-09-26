"""Requests for the real import API; never a packet/winner oracle."""
from copy import deepcopy


def document(lines):
    answer = dict(format='sakamoto-config-v1', rules=[], groups=[], edges=[], bindings=[], lists=[])
    for line in lines:
        fields = line.split()
        if fields[0] == 'lists':
            answer['lists'] = [dict(name=f'名单 {i}', source=f't19-source-{i}.txt',
                                   syntax=('native-v1', 'adblock-domain-v1', 'clash-domain-v1')[i],
                                   entries=[]) for i in range(int(fields[1]))]
        elif fields[0] == 'domain':
            index = int(fields[1]); mode, name = fields[2:]
            if name == 'xn--bcher-kva.example':
                name = 'BÜCHER.Example.'
            entry = f'{mode} {name}' if index == 0 else (
                f'||{name}^' if index == 1 else f'DOMAIN-SUFFIX,{name}')
            answer['lists'][index]['entries'].append(entry)
        elif fields[0] == 'group':
            answer['groups'].append(int(fields[1]))
        elif fields[0] == 'edge':
            answer['edges'].append(list(map(int, fields[1:])))
        elif fields[0] == 'bind':
            answer['bindings'].append(list(map(int, fields[1:])))
        else:
            index = len(answer['rules'])
            answer['rules'].append(dict(name=f'规则 {index}', source='t19-complete-source.json', definition=line))
    return answer


def edit_rule(document, field, value):
    result = deepcopy(document)
    fields = result['rules'][0]['definition'].split()
    fields[1], fields[0] = fields[0], '0'
    fields[field] = str(value)
    result['rules'][0]['definition'] = ' '.join(fields)
    return result


def roundtrip(call, label, applied):
    exported = call(label+'-export', None, 0)
    assert exported['stage'] == 'vpp' and exported['result'] == 0
    assert exported['saved_revision'] == applied['saved_revision']
    repeated = call(label+'-reimport', exported['configuration'], exported['saved_revision'])
    assert repeated == exported, ('non-idempotent export/import', label)
    return repeated


def failure_cases(call, label, current, save_failure=None):
    """Run once per profile. Independent verification reads every input/reply.

    The storage fault callback temporarily makes only this run's source directory
    unavailable, and must restore it in a finally block.
    """
    source = current['configuration']; revision = current['saved_revision']
    cases = []
    changed = deepcopy(source)
    fields = changed['rules'][0]['definition'].split(); fields[9] = '1'
    changed['rules'][0]['definition'] = ' '.join(fields)
    cases.append(('identity-content-conflict', changed, 'vpp', 2))
    changed = deepcopy(source); changed['rules'][0]['name'] += ' changed'
    cases.append(('identity-name-conflict', changed, 'vpp', 2))
    changed = deepcopy(source); changed['rules'].append(deepcopy(changed['rules'][0]))
    cases.append(('duplicate-identity', changed, 'vpp', 2))
    for name, syntax, entry in (
        ('invalid-name', 'native-v1', 'exact bad..example'),
        ('invalid-alabel', 'native-v1', 'exact xn--.example'),
        ('unicode-invalid', 'native-v1', 'exact bücher_foo.example'),
        ('url-path', 'native-v1', 'exact https://example.test/path'),
        ('unsupported-wildcard', 'native-v1', 'exact *.example.test'),
        ('filter-option', 'adblock-domain-v1', '||example.test^$script'),
        ('clash-extra-condition', 'clash-domain-v1', 'DOMAIN,example.test,Proxy'),
    ):
        changed = deepcopy(source)
        changed['lists'][0].update(syntax=syntax, entries=[entry])
        cases.append((name, changed, 'prepare', None))
    changed = deepcopy(source); changed['implicit_allow'] = True
    cases.append(('unknown-condition', changed, 'prepare', None))
    cases.append(('missing-list-reference', edit_rule(source, 16, '113f'), 'vpp', 10))
    changed = deepcopy(source); changed['edges'].append([10, 2, 10])
    cases.append(('group-cycle', changed, 'vpp', 11))
    changed = deepcopy(source)
    changed['bindings'].append([99, changed['bindings'][0][1], 2, 10, 0])
    cases.append(('mode-conflict', changed, 'vpp', 13))
    for name, request, stage, result in cases:
        response = call(label+'-'+name, request, revision)
        assert response['stage'] == stage, (name, response)
        if stage == 'vpp':
            assert response['result'] == result, (name, response)
        after = call(label+'-'+name+'-readback', None, 0)
        assert after['configuration'] == source
        assert (after['saved_revision'], after['active_revision']) == (revision, revision)
        assert after['active_versions'] == current['active_versions']
    stale = call(label+'-stale-revision', source, revision-1)
    assert stale['result'] == 2
    changed = edit_rule(source, 7, 1)  # valid source, deliberately unsupported compiler protocol
    if save_failure:
        failed = save_failure(lambda: call(label+'-save-failure', changed, revision))
        assert failed['result'] == 3 and failed['save_error'] == 3 and failed['compile_error'] == 0
        assert failed['configuration'] == source and failed['saved_revision'] == revision
        repaired = call(label+'-save-retry', source, revision)
        assert repaired['result'] == 0 and repaired['save_error'] == 0
        assert repaired['saved_revision'] == revision
    failed = call(label+'-compile-failure', changed, revision)
    assert failed['result'] == 4 and failed['save_error'] == 0 and failed['compile_error'] == 4
    assert (failed['saved_revision'], failed['active_revision']) == (revision+1, revision)
    assert failed['error_index'] == 0 and failed['active_versions'] == current['active_versions']
    readback = call(label+'-compile-failure-readback', None, 0)
    assert readback['configuration'] == failed['configuration']
    corrected = edit_rule(failed['configuration'], 7, source['rules'][0]['definition'].split()[7])
    restored = call(label+'-compile-retry', corrected, revision+1)
    assert restored['result'] == 0 and restored['compile_error'] == 0
    assert restored['saved_revision'] == restored['active_revision'] == revision+2
    return roundtrip(call, label+'-repaired', restored)
