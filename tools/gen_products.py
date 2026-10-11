#!/usr/bin/env python3
"""Offline, deterministic product inventory. Never executes checks.

Requires PyYAML >= 6. All paths are relative to repository root. Unknown facts
stay null; heuristics are candidates, never verified product fingerprints.
"""
from __future__ import annotations
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
import yaml
from catalog_scope import exclusion_reason

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_BLOCKS = ('http', 'requests', 'tcp', 'network', 'udp', 'dns', 'ssl',
                   'websocket', 'headless', 'javascript', 'code', 'file', 'whois')
FLAGS = ('brute_force', 'exploit', 'state_change', 'dos', 'external_interaction', 'authentication_attempts')
# Protocol names are deliberately not a product dictionary.
GENERIC_TOKENS = set('http https tls ssl smb smb2 ldap ldaps kerberos rpc rdp winrm ssh ftp smtp imap pop3 dns tcp udp network discovery detect detection version vuln cve panel safe auth brute windows'.split())


class InventoryLoader(yaml.CSafeLoader):
    """Reject repeated mapping keys instead of silently losing metadata."""


def unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise yaml.constructor.ConstructorError(
                'mapping', node.start_mark, f'duplicate key: {key}', key_node.start_mark)
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


InventoryLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def read_json(path):
    return json.loads((ROOT / path).read_text(encoding='utf-8'))


def write_json(path, value):
    (ROOT / path).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                      separators=(',', ':')) + '\n', encoding='utf-8')


def values(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def slug(value):
    return re.sub(r'[^a-z0-9.+]+', '-', str(value).lower()).strip('-')


def tokens(value):
    return set(re.findall(r'[a-z0-9]+', str(value).lower()))


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


def merge(dst, src):
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            merge(dst[key], value)
        else:
            dst[key] = value


def category_override(path, rules):
    """Shared by both generators; category schema is unchanged."""
    result = {}
    for rule in rules['overrides']:
        if path in rule.get('paths', []) or (rule.get('path_regex') and re.fullmatch(rule['path_regex'], path)):
            merge(result, rule.get('category', {}))
    return result


def main():
    rules = read_json('security/product-rules.json')
    snapshot = read_json('security/vendor-cves.json')
    categories = read_json('categories.json')['entries']
    issues, inventory, entries, products = [], {}, {}, {}
    rule_hits = Counter()
    aliases = {}
    for p in rules['products']:
        products[p['key']] = dict(p, cpes=[], checks=[])
        for alias in [p['product'], *p['aliases']]:
            aliases[(p['vendor'], slug(alias))] = p['key']

    def issue(path, kind, detail):
        issues.append({'path': path, 'kind': kind, 'detail': detail})

    def identity(vendor, product, cpe=None):
        vendor = slug(vendor) if vendor else None
        product_slug = slug(product)
        key = aliases.get((vendor, product_slug), (vendor or 'unknown') + '/' + product_slug)
        if key not in products:
            products[key] = {'key': key, 'vendor': vendor, 'product': product_slug,
                             'aliases': [], 'family': None, 'component': None,
                             'entity_type': 'unspecified', 'cpes': [], 'checks': []}
        if str(product) != products[key]['product'] and str(product) not in products[key]['aliases']:
            products[key]['aliases'].append(str(product))
        if cpe and cpe not in products[key]['cpes']:
            products[key]['cpes'].append(cpe)
        return key

    paths = sorted(p for p in (ROOT / 'nuclei-templates').rglob('*')
                   if p.is_file() and p.suffix.lower() in {'.yaml', '.yml'})
    paths += sorted((ROOT / 'nmap/scripts').rglob('*.nse'))
    parsed = {}
    for path in paths:
        rel = path.relative_to(ROOT).as_posix()
        raw = path.read_bytes()
        inv = {'kind': 'nse' if path.suffix == '.nse' else 'nuclei',
               'sha256': hashlib.sha256(raw).hexdigest(), 'status': 'pending'}
        inventory[rel] = inv
        try:
            text = raw.decode('utf-8')
            if inv['kind'] == 'nse':
                parsed[rel] = (None, text)
            else:
                # Safe loader has no object constructors / executable YAML tags.
                doc = yaml.load(text, Loader=InventoryLoader)
                if not isinstance(doc, dict):
                    inv['status'] = 'non_check'
                    continue
                if not doc.get('id'):
                    inv['status'] = 'non_check'
                    if any(k in doc for k in PROTOCOL_BLOCKS) and not rel.startswith(('nuclei-templates/profiles/', 'nuclei-templates/helpers/')):
                        issue(rel, 'missing_id', 'Protocol block without template id')
                    continue
                for field in ('info',):
                    if not isinstance(doc.get(field, {}), dict):
                        raise ValueError(f'{field} must be a mapping')
                for field in ('metadata', 'classification'):
                    if doc.get('info', {}).get(field) is not None and not isinstance(doc.get('info', {}).get(field), dict):
                        raise ValueError(f'info.{field} must be a mapping')
                if not any(k in doc for k in PROTOCOL_BLOCKS):
                    inv['status'] = 'workflow' if 'workflows' in doc else 'non_executable'
                    continue
                excluded = exclusion_reason(rel.removeprefix("nuclei-templates/"), text, doc)
                if excluded:
                    inv["status"] = "excluded_scope"
                    inv["exclusion_reason"] = excluded
                    continue
                parsed[rel] = (doc, text)
                info = doc.get('info') or {}
                md = info.get('metadata') or {}
                if isinstance(md, dict) and md.get('product'):
                    for p in values(md['product']):
                        if isinstance(p, str):
                            for v in values(md.get('vendor')) or [None]:
                                identity(v, p)
        except (UnicodeError, yaml.YAMLError, TypeError, ValueError) as exc:
            inv['status'] = 'parse_error'
            issue(rel, 'parse_error', str(exc))

    # Only existing explicit, single-token product names enter weak inference.
    token_products = defaultdict(set)
    tag_products = defaultdict(set)
    for key, product in products.items():
        for alias in [product['product'], *product['aliases']]:
            t = tokens(alias)
            if slug(alias) and slug(alias) not in GENERIC_TOKENS:
                tag_products[slug(alias)].add(key)
            if len(t) == 1 and next(iter(t)) not in GENERIC_TOKENS:
                token_products[next(iter(t))].add(key)

    ids = defaultdict(list)
    for rel, (doc, text) in sorted(parsed.items()):
        kind = inventory[rel]['kind']
        info = (doc.get('info') or {}) if doc else {}
        md = info.get('metadata') or {}
        md = md if isinstance(md, dict) else {}
        source_id = str(doc['id']) if doc else Path(rel).stem
        check_id = kind + ':' + rel  # path-qualified even if upstream ids collide
        ids[(kind, source_id)].append(rel)
        tags = info.get('tags', []) if doc else []
        tags = [str(x).lower() for x in tags] if isinstance(tags, list) else re.split(r'[,\s]+', str(tags).lower())
        cats_match = re.search(r'\bcategories\s*=\s*\{([^}]*)\}', text) if kind == 'nse' else None
        nse_cats = re.findall(r'["\']([^"\']+)["\']', cats_match[1]) if cats_match else []
        if kind == 'nse' and not cats_match:
            issue(rel, 'missing_categories', 'NSE category declaration not recognized')
        cat_key = rel.removeprefix('nuclei-templates/') if kind == 'nuclei' else rel
        cat = dict(categories.get(cat_key, {}))
        cat.update(category_override(rel, rules))
        e = {'id': check_id, 'source_id': source_id, 'path': rel, 'kind': kind,
             'source_sha256': inventory[rel]['sha256'], 'bindings': [],
             'name': info.get('name', source_id), 'severity': info.get('severity'),
             'references': values(info.get('reference')),
             'protocols': [], 'protocol_confidence': 'unknown', 'protocol_basis': [],
             'request_ports': {'mode': 'unknown', 'values': None, 'typical': None, 'raw': []},
             'affected_service': {'protocols': None, 'ports': None, 'typical_ports': None,
                                  'scope': 'unknown', 'description': None},
             'target': {'scope': 'unknown', 'service_required': True, 'product_required': True,
                        'port_is_fingerprint': False, 'fixed_endpoint_review': None},
             'evidence': {'kind': 'unknown', 'confidence': 'unknown', 'basis': []},
             'method_details': {'request_methods': [], 'matcher_types': [], 'extractor_names': [],
                                'dsl_functions': [], 'credential_placeholders': []},
             'impact': {'category': cat.get('impact'), 'flags': {f: None for f in FLAGS},
                        'basis': ['categories.json and source labels; not a safety verdict']},
             'requirements': {'account': None, 'privileges': None, 'version': None,
                              'components': None, 'user_interaction': None,
                              'source_conditions': info.get('description'), 'script_arguments': []},
             'vulnerability_requirements': {'account': None, 'privileges': None, 'components': None,
                                            'user_interaction': None, 'source_conditions': None},
             'engine': {'wscan_support': 'unknown', 'features': [], 'modules': [], 'binaries': None},
             'version_constraints': None, 'recommendation': 'review_required',
             'source_labels': {'tags': tags, 'nse_categories': nse_cats}}

        def bind(key, confidence, basis):
            existing = next((b for b in e['bindings'] if b['product'] == key), None)
            if existing:
                existing['basis'].append(basis)
            else:
                e['bindings'].append({'product': key, 'confidence': confidence, 'basis': [basis]})

        if doc:
            if len(values(md.get('vendor'))) > 1 and len(values(md.get('product'))) > 1:
                issue(rel, 'ambiguous_metadata_pairs',
                      'Multiple vendors and products; possible pairs retained as candidates, relation not established')
            for p in values(md.get('product')):
                if isinstance(p, str):
                    for v in values(md.get('vendor')) or [None]:
                        confidence = 'inferred' if len(values(md.get('vendor'))) > 1 and len(values(md.get('product'))) > 1 else 'explicit'
                        bind(identity(v, p), confidence, {'source': 'info.metadata', 'vendor': v, 'product': p})
            cpes = values((info.get('classification') or {}).get('cpe')) + values(md.get('cpe'))
            for cpe in cpes:
                if isinstance(cpe, str) and cpe.startswith('cpe:2.3:'):
                    parts = re.split(r'(?<!\\):', cpe)
                    if len(parts) >= 5 and parts[3] not in ('*', '-') and parts[4] not in ('*', '-'):
                        bind(identity(parts[3], parts[4], cpe), 'explicit', {'source': 'CPE', 'value': cpe})
            blocks = [k for k in PROTOCOL_BLOCKS if k in doc]
            e['engine']['features'] = blocks + (['flow'] if 'flow' in doc else [])
            transport = {'requests': 'http', 'headless': 'http', 'network': 'tcp', 'ssl': 'tls'}
            e['protocols'] = sorted({transport.get(k, k) for k in blocks if k not in ('code', 'javascript', 'file')})
            e['protocol_confidence'] = 'explicit' if e['protocols'] else 'unknown'
            e['protocol_basis'] = [{'source': 'protocol_blocks', 'values': blocks}]
            if 'file' in blocks:
                e['target']['scope'] = 'local_files'
            elif 'code' in blocks or 'javascript' in blocks:
                e['target']['scope'] = 'review_required'
            else:
                e['target']['scope'] = 'selected_service_candidate'
            endpoint_values = []
            for block in blocks:
                for request in values(doc[block]):
                    if not isinstance(request, dict):
                        continue
                    if request.get('method'):
                        e['method_details']['request_methods'].append(str(request['method']))
                    for raw in values(request.get('raw')):
                        if isinstance(raw, str):
                            m = re.match(r'([A-Z]+)\s+\S+\s+HTTP/', raw)
                            if m:
                                e['method_details']['request_methods'].append(m[1])
                                endpoint_values.append(raw.splitlines()[0].split()[1])
                            host = re.search(r'(?mi)^Host:\s*(\S+)', raw)
                            if host:
                                endpoint_values.append(host[1])
                    for matcher in values(request.get('matchers')):
                        if isinstance(matcher, dict) and matcher.get('type'):
                            e['method_details']['matcher_types'].append(str(matcher['type']))
                            if matcher['type'] == 'dsl':
                                for expression in strings(matcher.get('dsl')):
                                    e['method_details']['dsl_functions'].extend(re.findall(r'\b([a-zA-Z_]\w*)\s*\(', expression))
                    for extractor in values(request.get('extractors')):
                        if isinstance(extractor, dict) and extractor.get('name'):
                            e['method_details']['extractor_names'].append(str(extractor['name']))
                    endpoint_values.extend(list(strings({k: request[k] for k in ('host', 'port', 'path') if k in request})))
                    if 'port' in request:
                        endpoint_values.extend(str(p) for p in values(request['port']))
            e['request_ports']['raw'] = sorted(set(endpoint_values))
            numbers = set()
            for s in endpoint_values:
                if re.fullmatch(r'\d+(?:,\d+)*', s):
                    numbers.update(int(p) for p in s.split(',') if 0 < int(p) < 65536)
                numbers.update(int(p) for p in re.findall(r':(\d{1,5})(?:/|$)', s) if 0 < int(p) < 65536)
            if numbers:
                e['request_ports'].update(mode='source_literal', values=sorted(numbers))
                e['target']['fixed_endpoint_review'] = True
            elif any(any(m in s for m in ('{{BaseURL}}', '{{RootURL}}', '{{Hostname}}')) for s in endpoint_values) and set(e['protocols']) <= {'http'}:
                e['request_ports']['mode'] = 'selected_service'
            e['engine']['modules'] = sorted(set(re.findall(r'require\(["\']([^"\']+)["\']\)', text)))
            e['method_details']['credential_placeholders'] = sorted(set(re.findall(
                r'\{\{\s*((?:[A-Za-z_]*)(?:username|password|token|api_key|secret)[A-Za-z_]*)\s*\}\}', text, re.I)))
            if any('interactsh-url' in s for block in blocks for s in strings(doc[block])):
                e['engine']['features'].append('oast')
                e['impact']['flags']['external_interaction'] = True
            if any(re.search(r'https?://(?!\{\{)', s) for s in endpoint_values):
                e['target']['fixed_endpoint_review'] = True
                e['target']['scope'] = 'review_required'
            # Redirects also need a same-service guard in the calling engine.
            if re.search(r'(?m)^\s*(?:host-)?redirects:\s*true', text):
                e['engine']['features'].append('redirect_guard_required')
        else:
            desc = re.search(r'description\s*=\s*\[\[(.*?)\]\]', text, re.S)
            e['requirements']['source_conditions'] = desc[1].strip() if desc else None
            e['references'] = sorted(set(re.findall(r'https?://[^\s<>"\']+', desc[1]))) if desc else []
            e['requirements']['script_arguments'] = re.findall(r'--\s*@args\s+([^\n]+)', text)
            rule = re.search(r'(?m)^(portrule|hostrule|prerule|postrule)\s*=\s*([^\n]+)', text)
            if rule:
                e['target']['scope'] = 'selected_service_candidate' if rule[1] == 'portrule' else 'host_or_global'
                e['protocol_basis'].append({'source': rule[1], 'value': rule[2]})
            # NSE rules/libraries can choose other ports: preserve raw rule, never
            # interpret the first number in a Lua expression as a target port.
            e['request_ports']['raw'] = [rule[2]] if rule else []
            for r in rules['nse_protocol_prefixes']:
                if Path(rel).stem == r['prefix'] or Path(rel).stem.startswith(r['prefix'] + '-'):
                    e['protocols'] = r['protocols']
                    e['protocol_confidence'] = 'inferred'
                    e['protocol_basis'].append({'source': 'curated_filename_convention', 'prefix': r['prefix']})
                    break
            e['engine']['features'] = ['nmap_nse']
            e['engine']['modules'] = sorted(set(re.findall(r'require\s*\(?["\']([^"\']+)', text)))
            if 'external' in nse_cats:
                e['impact']['flags']['external_interaction'] = True

        labels = set(tags + nse_cats)
        if cat.get('types') == ['Подбор учётных данных'] or labels & {'brute', 'bruteforce', 'credential-stuffing', 'creds-stuffing'}:
            e['impact']['flags']['brute_force'] = True
        for tag, flag in [('exploit', 'exploit'), ('dos', 'dos')]:
            if tag in labels:
                e['impact']['flags'][flag] = True
        if labels & {'version', 'discovery', 'detect', 'detection', 'panel', 'tech'}:
            e['evidence'] = {'kind': 'interface' if labels & {'panel', 'detect', 'detection', 'discovery', 'tech'} else 'version',
                             'confidence': 'inferred', 'basis': ['source labels; matcher semantics require review']}
        if not e['bindings']:
            for tag in sorted(set(tags)):
                matches = tag_products.get(slug(tag), set())
                if len(matches) > 1:
                    issue(rel, 'ambiguous_product_tag', {'tag': tag, 'candidates': sorted(matches)})
                for key in sorted(matches):
                    bind(key, 'inferred', {'source': 'exact_known_product_tag', 'value': tag,
                                          'limitation': 'A tag may name an integration or component; requests need review'})
            bag = tokens(Path(rel).stem) | tokens(info.get('name', '')) | set(tags)
            for token in sorted(bag & token_products.keys()):
                matches = token_products[token]
                if len(matches) > 1:
                    issue(rel, 'ambiguous_token', {'token': token, 'candidates': sorted(matches)})
                for key in sorted(matches):
                    bind(key, 'inferred', {'source': 'whole_token', 'value': token,
                                          'limitation': 'May name a plugin, artifact or third-party integration'})

        for rule in rules['overrides']:
            if rel not in rule.get('paths', []) and not (rule.get('path_regex') and re.fullmatch(rule['path_regex'], rel)):
                continue
            rule_hits[rule['id']] += 1
            if 'products' in rule:
                e['bindings'] = []
                for key in rule['products']:
                    if key not in products:
                        raise ValueError('Unknown curated product ' + key)
                    bind(key, 'curated', {'source': 'security/product-rules.json', 'rule': rule['id'], 'reason': rule['reason']})
            merge(e, rule.get('entry', {}))
            e['impact']['basis'].append(rule['reason'])

        # Reviewed snapshot supplies explicit comparison semantics, never derive
        # version ranges from a CVE id or free-form prose.
        for item in snapshot['entries']:
            expected = f"nuclei-templates/http/cves/{item['id'].split('-')[1]}/{item['id']}-{item['product']}-version.yaml"
            if rel != expected or not item['ranges']:
                continue
            key = 'mikrotik/routeros' if item['product'] == 'mikrotik' else 'gitlab/gitlab'
            e['bindings'] = []
            bind(key, 'curated', {'source': 'security/vendor-cves.json', 'id': item['id'], 'references': item['references']})
            e['evidence'] = {'kind': 'version', 'confidence': 'curated', 'basis': ['GET + product marker + observed_version + compare_versions']}
            e['version_constraints'] = {'any_of': item['ranges'], 'all_of_within_group': True,
                                        'comparison': 'numeric_release_components', 'prerelease': 'excluded',
                                        'source': 'security/vendor-cves.json', 'references': item['references']}
            e['affected_service']['description'] = item['ports']
            e['vulnerability_requirements']['source_conditions'] = item['conditions']
            e['requirements']['components'] = e['requirements']['components'] or 'HTTP(S) interface publishing the product version'
            e['requirements']['account'] = 'not_required_for_probe'
            e['requirements']['version'] = 'public stable version in current product response'
            e['requirements']['user_interaction'] = False
            e['request_ports'].update(mode='selected_service', values=None, typical=[80, 443, 8080, 8443])
            e['impact']['flags'] = {f: False for f in FLAGS}
            e['recommendation'] = 'service_candidate'
            e['impact']['basis'].append('gen_vendor_cves.py: GET version checks; exploitation prerequisites separate')

        if len(e['bindings']) > 1:
            issue(rel, 'multiple_product_bindings', [b['product'] for b in e['bindings']])
        if not e['bindings']:
            # Unknown identity is not proof the check is product-agnostic.
            e['product_status'] = 'generic' if rel in rules['generic_paths'] else 'unresolved'
        else:
            e['product_status'] = 'bound'
        for b in e['bindings']:
            products[b['product']]['checks'].append(check_id)
        for field in e['method_details']:
            e['method_details'][field] = sorted(set(e['method_details'][field]))
        entries[check_id] = e
        inventory[rel]['status'] = 'indexed'

    for (kind, source_id), sources in sorted(ids.items()):
        if len(sources) > 1:
            issue(sources[0], 'duplicate_source_id', {'kind': kind, 'id': source_id, 'paths': sources})
    for rule in rules['overrides']:
        if not rule_hits[rule['id']]:
            issue('security/product-rules.json', 'unmatched_rule', rule['id'])
    for path in rules['generic_paths']:
        if path not in inventory:
            issue(path, 'unmatched_generic_path', 'Curated path is absent')
    for p in products.values():
        for field in ('checks', 'aliases', 'cpes'):
            p[field] = sorted(set(p[field]))
    counts = {'inventory_files': len(inventory), 'checks': len(entries), 'products': len(products),
              'parse_errors': sum(i['kind'] == 'parse_error' for i in issues),
              'nselib_lua_files_not_checks': sum(1 for p in (ROOT / 'nmap/nselib').rglob('*.lua') if p.is_file()),
              'products_with_checks': sum(bool(p['checks']) for p in products.values()),
              'by_kind': dict(Counter(e['kind'] for e in entries.values())),
              'inventory_status': dict(Counter(v['status'] for v in inventory.values())),
              'bindings_by_confidence': dict(Counter(b['confidence'] for e in entries.values() for b in e['bindings'])),
              'product_status': dict(Counter(e['product_status'] for e in entries.values())),
              'issues_by_kind': dict(Counter(i['kind'] for i in issues)),
              'unknown': {'protocols': sum(not e['protocols'] for e in entries.values()),
                          'request_ports': sum(e['request_ports']['mode'] == 'unknown' for e in entries.values()),
                          'affected_ports': sum(e['affected_service']['ports'] is None for e in entries.values()),
                          'affected_protocols': sum(e['affected_service']['protocols'] is None for e in entries.values()),
                          'affected_typical_ports': sum(e['affected_service']['typical_ports'] is None for e in entries.values()),
                          'account': sum(e['requirements']['account'] is None for e in entries.values()),
                          **{f: sum(e['requirements'][f] is None for e in entries.values()) for f in
                             ('privileges', 'version', 'components', 'user_interaction')},
                          'evidence': sum(e['evidence']['kind'] == 'unknown' for e in entries.values()),
                          'wscan_support': sum(e['engine']['wscan_support'] == 'unknown' for e in entries.values()),
                          **{f: sum(e['impact']['flags'][f] is None for e in entries.values()) for f in FLAGS}}}
    source_digest = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
    inputs = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in
              ('security/product-rules.json', 'security/vendor-cves.json', 'tools/gen_products.py', 'tools/catalog_scope.py')}
    inputs["security/catalog-scope.json"] = hashlib.sha256((ROOT / "security/catalog-scope.json").read_bytes()).hexdigest()
    inputs['categories.entries'] = hashlib.sha256(json.dumps(categories, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    write_json('products.json', {'schema_version': 1, 'source_digest': source_digest, 'input_sha256': inputs,
                                'rules': 'security/product-rules.json', 'counts': counts,
                                'products': products, 'checks': entries, 'inventory': inventory})
    write_json('security/product-index-issues.json', {'schema_version': 1, 'issues': issues})
    report = ['# Отчёт индекса продуктов', '',
              'Генерируется `python3 tools/gen_products.py`; источники локальные, сетевых запросов нет.', '',
              '## Выполнено', '',
              '- Полная инвентаризация YAML/YML Nuclei и самостоятельных NSE, включая custom и все протоколы.',
              '- Разбор метаданных/CPE, точных токенов, курируемых исключений; стабильные пути, ID и SHA-256.',
              '- Разделены протокол проверки, порты запроса и затронутый сервис, доказательство и воздействие.',
              '- Курируемые категории применяются обоими генераторами; контракт интеграции и примеры описаны отдельно.', '',
              '## Покрытие', '', '```json', json.dumps(counts, ensure_ascii=False, indent=2), '```', '',
              '## Исправленные категории и разобранные случаи', '']
    for rule in rules['overrides']:
        report.append(f"- `{rule['id']}` ({rule_hits[rule['id']]} файлов): {rule['reason']}")
    report += ['', '## Ошибки и неоднозначности', '',
               'Полный перечень путей, ошибок разбора, конфликтов CPE/metadata, неоднозначных токенов и дублированных upstream ID: '
               '[product-index-issues.json](product-index-issues.json). Ошибочные файлы остаются в inventory, а не исчезают.', '',
               '## Ограничения и оставшаяся работа', '',
               '- Это полная автоматизированная инвентаризация, а не ручная верификация поведения каждой проверки. '
               'Вручную разобраны перечисленные курируемые случаи. Остальные сведения по тегам имеют inferred/unknown.',
               '- Непривязанные проверки разделены на явно общие и unresolved. Unresolved нельзя объявлять общими или безопасными.',
               '- У неоднозначных привязок остаются все кандидаты. Несколько CPE/metadata не доказывают, что запрос подходит каждому продукту.',
               '- Внешние источники не загружались; ссылки взяты из локальных шаблонов и ранее подготовленного CVE-среза. '
               'Диапазоны перенесены со ссылкой на этот срез; их свежесть заново не проверялась.',
               '- Порты из TCP YAML сохраняются как source_literal, а не как разрешение переходить на соседний сервис. '
               'Lua не исполняется; portrule хранится буквально, hostrule/global запрещают обычную рекомендацию для сервиса.',
               '- Теги safe и severity не доказывают отсутствие побочных эффектов. Неизвестные флаги воздействия остаются null. '
               'Общая классификация остальных исходных категорий сохранена и требует дальнейшего курирования.',
               '- Поведение requirements/components и affected_service.description может оставаться исходным текстом; '
               'потребитель не должен превращать текст или типичный порт в машинное условие.',
               '- Код основного wscan здесь отсутствует: поддержка движка везде unknown. Нужны capability handshake, '
               'контроль выбранного сервиса, фильтры воздействия и отображение доказательств; см. '
               '[product-index-integration.md](product-index-integration.md).',
               '- Каталог внешних целей исключает локальные, облачные и self-contained проверки по security/catalog-scope.json; причины сохранены в inventory (excluded_scope).',
               '- Файлы workflow/profile/helper/config включены в inventory отдельно от исполняемых проверок; nselib — библиотеки.',
               '- Ручные CVE-позиции без диапазона не создают проверок и рекомендаций (включая GitLab AI Gateway).',
               '- Дальше: вручную разобрать unresolved и конфликты, установить неизвестные требования/порты/воздействие, '
               'подключить индекс в wscan. Эти неизвестные факты невозможно достоверно установить эвристикой.', '',
               '## Выполненные действия', '',
               'Чтение исходников и генерация products.json/categories.json. Тесты, сборка, '
               'запуск шаблонов, NSE и обращения к целевым устройствам не выполнялись. Коммит и публикация не выполнялись.', '']
    (ROOT / 'security/product-index-report.md').write_text('\n'.join(report), encoding='utf-8')
    print(json.dumps(counts, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
