from pwn import remote, context
import json

signatures = [
    (0, 815060882371267083010771166165802965323452486341),
    (0, 3138550868100870823103528253093415089966498869253147385211),
    (0, 4184734490529474136680948643120963064566730837229712351501),
    (0, 4707826301743775793469658838134737051866846821217994834646),
    (0, 5021681388472356787542884955143001444246916411610964324533),
    (0, 5230918112958077450258369033148511039166962805206277317791),
    (0, 1793457638798346058577549418480412741957170358812733864929),
    (0, 2353913150871887896734829419067368525933423410608997417323),
    (0, 3487278741972051633505579355432340692777975203470851545194),
    (0, 5649391561929518775689337189159530229007055592396903304307),
    (0, 570645612381976513291550591471530016357545248955117706402),
    (0, 5754009924172379107047079228162285026467078789194559800936),
    (0, 4345685816868860596684105530122715560774658147997617926390),
    (0, 4035279687092513411206669420828235877862182565997788074505),
    (0, 5858628286415239438404821267165039823927101985992216297565),
    (0, 4315507443129284330285309421121713769850309091895919850702),
    (0, 1846206392808733217738247894052415660882457460661039053338),
    (0, 1743639370986025816752789677716170346388987601735425772597),
    (0, 330373775589565349800371395062464746312263038868752356338),
    (0, 5963246648658099769762563306167794621387125182789872794194),
    (0, 597819212932782019525849806160137580652390119604244621643),
    (0, 285322806190988256645775295735765008178772624477558853201),
    (0, 3547927067862691774445066503665197319353884131160887051278),
    (0, 2877004962086189553523539614081142513233539394597279900468),
    (0, 3515176971849143663042892760299023894356261191595329778539),
    (0, 2172842908434430298342052765061357780387329073998808963195),
    (0, 1162426247324017211168526451810780230925991734490283848398),
    (0, 5156190711239597087521229422002147445814688669590315179293),
    (0, 4112583895626275703284526418046754911301465643303360547720),
    (0, 6067865010900960101120305345170549418847148379587529290823),
    (0, 5062178818886518708976322666529427306785344267577242244786),
    (0, 2157753721564642165142654710560856884925154545947959925351),
    (0, 4374949694385112680321043145941216014630644931773600758188),
    (0, 923103196404366608869123947026207830441228730330519526669),
    (0, 1614111874837005364482667768331294351144873026399115229802),
    (0, 4010370553186353290294289550446114680078091187459134028339),
    (0, 4580587752871768689349664365101739582104866536250275517744),
    (0, 165186887794782674900185697531232373156131519434376178169),
    (0, 5633296429214074041451894792158277862769682564787767498184),
    (0, 2981623324329049884881281653083897310693562591394936397097),
    (0, 5358501481447533844307899924248117967024820000651778839736),
    (0, 3437460474159731391680819614668098297209792446393543452862),
    (0, 145979110144226549911792011771786748370534831128053366754),
    (0, 3281212270788834510240782359455912010972983698830200568641),
    (0, 1952876095471746479468273755721679941309033995330738765855),
    (0, 1773963533931345887222533251832598659676942065580443525639),
    (0, 4407326750395223959339411022294057842989004903837388252362),
    (0, 1438502481043094776761769807040571256616769697298639950234),
    (0, 3843123511477867016274386730169235542432278493077729000179),
    (0, 4896139353617912213439341091737541454061727982389086031310),
    (0, 615402130936244405912749298017471886960819153553679684446),
    (0, 4224972321910555531088921094118708397077261923590825623638),
    (0, 947487054413368056472784574875834778798176625486531901113),
    (0, 581213123662008605584263225905390115462995867245141924199),
    (0, 3880390163708403760959783772199941411531825913700728911729),
    (0, 5716646223313138925678509422589103229790941721386578731687),
    (0, 2202491836992082037878720272746174586693152604017198213473),
    (0, 2056291947813137851642263209023377455650732821651680273860),
    (0, 4574836858007497181818817157281039131494155562918401198336),
]

context.log_level = "error"

for signature in signatures:
    conn = remote("socket.cryptohack.org", 13381)
    response = conn.recvline()

    r, s = signature
    packet = {"option": "verify", "msg": "unlock", "r": hex(r), "s": hex(s)}
    packet = json.dumps(packet).encode()
    conn.sendline(packet)
    # conn.interactive()
    response = conn.recvline()
    response = json.loads(response)

    print(response)
    # if "flag" in response:
    #     print(response)
    #     conn.close()
    #     break

    conn.close()
