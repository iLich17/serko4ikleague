import json, random
from pathlib import Path
root=Path('/tmp/f1')
drivers=list(json.load(open(root/'drivers.json',encoding='utf8')).keys())
teams=['McLaren','Ferrari','Mercedes','Red Bull Racing','Aston Martin','Williams','Haas','Alpine','Visa Cash App RB','Kick Sauber']
gps=['Австралия','Китай','Япония','Бахрейн','Майами','Канада','Испания','Монако','Великобритания','Австрия','Бельгия','Венгрия','Нидерланды','Италия','Сингапур']
sessions=['race','sprint','race','race','race','sprint','race','race','race','race','race','race','race','sprint','race']
rng=random.Random(20250119)
shuffled=drivers[:]; rng.shuffle(shuffled)
# 2-3 drivers per team; first 20 exactly 2, remaining 8 create some 3-driver teams (league-style historical roster)
assignment={d:teams[i%len(teams)] for i,d in enumerate(shuffled)}
# force several recognizable season-to-season transfers relative to current drivers.json
season1_team={
 'Alexander Frame':'Ferrari','Antonio Londyx':'Mercedes','Ayrton Senna':'Red Bull Racing','Banana Leclerc':'McLaren',
 'Bogdan Strolov':'Alpine','Bruno Guimaraes':'Mercedes','Cristiano Ronaldo':'Williams','Dmitry Shelepa':'Haas',
 'Esteban Ocon':'Alpine','Gleb Becker':'Kick Sauber','Hasan Tigiev':'Aston Martin','Jorginho Ferreira':'Ferrari',
 'Lewis Hamilton':'Mercedes','Mark Freynem':'Haas','Max Raze':'Red Bull Racing','Nikita Sprite':'Visa Cash App RB',
 'Oscar Piastri':'Ferrari','Rock Johnson':'Williams','Sam Baker':'McLaren','Sergey Nabokov':'Aston Martin',
 'Shishka Hamilton':'Williams','Steven Lindbald':'Red Bull Racing','Timur Zaripov':'Visa Cash App RB','Toni Martinez':'Alpine',
 'Vova Scott':'Kick Sauber','Wang Kim':'McLaren','Yan Morel':'Haas','Zayats Burmaldayats':'Aston Martin'
}
assignment.update(season1_team)
# Points according to F1-style scoring used by the site
race_pts=[25,18,15,12,10,8,6,4,2,1]
sprint_pts=[8,7,6,5,4,3,2,1]
races=[]
for rnd,(gp,sess) in enumerate(zip(gps,sessions),1):
    pool=drivers[:]
    rng.shuffle(pool)
    # usually 18-24 starters; add a few DNFs/DSQs
    starters=pool[:rng.randint(18,24)]
    finishers=starters[:]
    rng.shuffle(finishers)
    pts=sprint_pts if sess=='sprint' else race_pts
    results=[]
    nscored=min(len(pts),len(finishers))
    for pos,d in enumerate(finishers[:nscored],1):
        results.append({'driver':d,'team':assignment[d],'position':pos,'points':pts[pos-1],'gap':'GAP' if pos==1 else f'+{rng.uniform(1.2,58.0):.3f}'})
    for pos,d in enumerate(finishers[nscored:],nscored+1):
        status='DNF' if rng.random()<0.85 else 'DSQ'
        results.append({'driver':d,'team':assignment[d],'position':status,'points':0,'gap':status})
    # Make 1-3 additional DNS entries to create realistic variation
    for d in pool[len(starters):len(starters)+rng.randint(0,2)]:
        results.append({'driver':d,'team':assignment[d],'position':'DNS','points':0,'gap':'DNS'})
    races.append({'round':rnd,'grandPrix':gp,'session':sess,'results':results})
season1={'season':1,'name':'Сезон 1','drivers':{d:{'name':d,'team':assignment[d]} for d in drivers},'races':races}
json.dump(season1,open(root/'season1.json','w',encoding='utf8'),ensure_ascii=False,indent=2)
print('season1 created', len(races), 'races', len(drivers),'drivers')
