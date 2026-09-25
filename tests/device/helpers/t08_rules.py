"""Request construction for T08 representative competing rules (no evaluator)."""
def request(prior, uid, protocol, scenario, mode, pixel=False):
    prefix = 'rule.' if pixel else 'config.rule.'
    # priority, action, expression, effective mode
    rules = {
        'chain': [(10,2,'0d020ca09ea09e01',0),
                  (20,1,'0ca09ea19e',0), (30,2,'0ca19ea29e',mode), (40,1,'',0)],
        'early-drop': [(0,2,'',mode), (10,2,'0e02',0)],
        'static-first': [(0,1,'',0), (10,2,'0e02',0)],
    }[scenario]
    lines=[]
    for i,(priority,action,expression,effective_mode) in enumerate(rules):
        version=prior.get(prefix+str(i)+'.version','0')
        lines.append(f'0 {version} 4294967295 4294967295 4294967295 {priority} 0 {protocol} 0 {action} * * 0 65535 0 65535'+(' '+expression if expression else ''))
    lines += [f'bind {i+1} {uid} 1 {i} {r[3]}' for i,r in enumerate(rules)]
    return lines
