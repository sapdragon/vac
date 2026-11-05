import argparse
import json
import struct
import subprocess
from pathlib import Path

import compare_vac_worker as cmp

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT.parent / 'vac-research/ptr_0x0D2058E8_crc_a8848995_GetProcessList_plus2scan/module.dll'
REBUILD = ROOT / 'build/Release/Win32/process_file_identity.dll'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', default='')
    args = ap.parse_args()
    dest = ROOT / 'build/a8848995_parity'
    dest.mkdir(parents=True, exist_ok=True)
    fixtures = dest / 'fixtures'
    fixtures.mkdir(exist_ok=True)
    (fixtures / 'plain.txt').write_bytes(b'ordinary file\n' * 50)
    (fixtures / 'empty').write_bytes(b'')
    (fixtures / 'short-mz').write_bytes(b'MZ' + b'\0' * 8)
    (fixtures / 'not-pe').write_bytes(b'X' * 512)
    (fixtures / 'sub').mkdir(exist_ok=True)
    (fixtures / 'sub/inner').write_bytes(b'content')
    (fixtures / '\u0442\u0435\u0441\u0442.txt').write_bytes(b'utf8')
    many=dest/'many'; many.mkdir(exist_ok=True)
    for i in range(205): (many/str(i)).touch()
    cases = []
    for name, path in [('missing', fixtures/'absent'), ('plain',fixtures/'plain.txt'),
                       ('empty',fixtures/'empty'), ('short',fixtures/'short-mz'),
                       ('notpe',fixtures/'not-pe'), ('pe',REBUILD), ('directory',fixtures),
                       ('utf8',fixtures/'\u0442\u0435\u0441\u0442.txt')]:
        cases.append(('file_'+name, 0x013B4330, str(path), 32, 0, 0))
    for name, path, inc, exc in [('missing',fixtures/'absent',0,0), ('all',fixtures,0,0),
                ('files',fixtures,2,1), ('dirs',fixtures,1,0), ('exclude_empty',fixtures,0,0x1000),
                ('utf8',fixtures,0x2000,0), ('asfile',fixtures/'plain.txt',0,0),
                ('limit',many,0,0), ('profile','',0xffff,0xffff)]:
        cases.append(('dir_'+name,0x0CA11165,str(path),56,inc,exc))
    results=[]
    pe1, pe2 = cmp.PeImage(ORIGINAL), cmp.PeImage(REBUILD)
    packet=cmp.read_packet(ORIGINAL.parent/'inputVacPacket_ScanId_4.bin')
    node=cmp.find_single_node(cmp.PeImage(ORIGINAL),packet.module_id,packet.version,'packet')
    seed=cmp.ice_decrypt_buffer(node.ice_key[:8],packet.encrypted_payload)[:32]
    def run(name, mid, payload, cap=4096):
        if args.only and args.only not in name: return
        n1=cmp.find_single_node(pe1, mid, 1, 'original')
        n2=cmp.find_single_node(pe2, mid, 1, 'rebuild')
        info, a,b=cmp.invoke_workers_with_powershell(ORIGINAL,n1.worker_rva,REBUILD,n2.worker_rva,bytes(payload),cap)
        count,first,ranges=cmp.diff_ranges(a,b,4096)
        equal=all(info['original'][x]==info['rebuild'][x] for x in ('ret','size'))
        case=dest/name; case.mkdir(exist_ok=True)
        (case/'original.bin').write_bytes(a); (case/'rebuild.bin').write_bytes(b)
        (case/'payload.bin').write_bytes(payload)
        result=dict(case=name,diff=count,first=first,ranges=ranges,envelope_equal=equal)
        results.append(result)
        print(json.dumps(result),flush=True)
        return a
    for name,mid,path,off,inc,exc in cases:
        payload=bytearray(160); payload[:32]=seed
        encoded=path.encode('utf-8')
        if len(encoded)>=160-off: raise ValueError(path)
        payload[off:off+len(encoded)]=encoded
        if off==56: struct.pack_into('<II',payload,48,inc,exc)
        run(name,mid,payload)
    for mid, threshold in ((0x013B4330,0x138),(0x0CA11165,4096),(0x0B2D8276,0xD88)):
        for cap in (threshold-1,threshold):
            payload=bytearray(160); payload[:32]=seed
            if mid==0x0CA11165:
                path=str(fixtures).encode(); payload[56:56+len(path)]=path
            run(f'capacity_{mid:x}_{cap}',mid,payload,cap)
    for pid in (0,4,0xffffffff):
        payload=bytearray(160); payload[:32]=seed; struct.pack_into('<I',payload,96,pid)
        run('process_pid_'+str(pid),0x0B2D8276,payload)
    for arch in ('System32','SysWOW64'):
        startup=subprocess.STARTUPINFO(); startup.dwFlags|=subprocess.STARTF_USESHOWWINDOW
        proc=subprocess.Popen([fr'C:\Windows\{arch}\WindowsPowerShell\v1.0\powershell.exe',
            '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 120'],startupinfo=startup)
        try:
            import time
            time.sleep(1)
            payload=bytearray(160); payload[:32]=seed; struct.pack_into('<I',payload,96,proc.pid)
            run('process_'+arch,0x0B2D8276,payload)
        finally:
            proc.terminate(); proc.wait()
    (dest/'results.json').write_text(json.dumps(results,indent=2))
    return int(any(x['diff'] or not x['envelope_equal'] for x in results))

if __name__=='__main__': raise SystemExit(main())
