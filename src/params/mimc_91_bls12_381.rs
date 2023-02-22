use crate::MiMCParameters;

#[derive(Debug, Clone, Default)]
pub struct MIMC_91_BLS12_381_PARAMS;

impl MiMCParameters for MIMC_91_BLS12_381_PARAMS {
    const ROUNDS: usize = 91;
    const EXPONENT: usize = 7;
}

pub const MIMC_91_BLS12_381_ROUND_KEYS: [&str; MIMC_91_BLS12_381_PARAMS::ROUNDS] = [
    "0",
    "12229571979494343421523498192994790888706681595080595532007690219807782377702",
    "6605736681987382703605222894257625007997931759513831581260254358965781123914",
    "21563031067884617171767980895088617736997752952362261406202638359434480011994",
    "45150809963158715945364450855316242292494248066013872541574037700775750570638",
    "2783199252216704359678636841588760785968062876267047197695943661964328799193",
    "37675997501327469169986779142170221237506413731849468111237337137402498147100",
    "33078221467132027577066547520855785239738323578333319141435949876703126572006",
    "7832430582107555992021963624072298844572057577226832693815878561038626850813",
    "38918157763382500523650237841137756820100195125783321324309382924279697667347",
    "17842890472060042114622160636973816584485785390241409997994582387644011967856",
    "2328578133874638321204109133272291977925471786551359923952761681594468714100",
    "48817184979784641099782743311238476834173212037692614969802520195027289140134",
    "2632385916954580941368956176626336146806721642583847728103570779270161510514",
    "30920265292369210622889348233446067935240003535430617042439514958349587957009",
    "11482807709115676646560379017491661435505951727793345550942389701970904563183",
    "21589691694524633330640635453726873963337650104286244658701700741668560037111",
    "4004431812584608476536457305571159570997954086091700803721247322501084096246",
    "7636465386286964043574138485843662851067517063346876202693101566261784297117",
    "43653568181609868176213174871034079442167018649339268688293045526152610757544",
    "19825444354178182240559170937204690272111734703605805530888940813160705385792",
    "29932318584405475312232167075561498183052027603469513741658934747202763619930",
    "48178332573508560780401322037296402480965391326816142572621747273106064178456",
    "10864774797625152707517901967943775867717907803542223029967000416969007792571",
    "23264507004406229457083230143313345768511917623766306816237203877330530622112",
    "8016432597002663716757506604803568673067070938399965071719832947774490112348",
    "26541560178305768406990275904780509677504358857414110587166352678951045341623",
    "30374954015428998258746339266834146972048587598679377367701822012192219427643",
    "4820174593402577770995926197482573699146527766289648113021927021323477179339",
    "6673623808548927673627918736019755503308871965225492710258312939979172784232",
    "29542416046229344527091316628826512362712844222264159066024709236352333681177",
    "6032365105133504724925793806318578936233045029919447519826248813478479197288",
    "49142214446078777131853328750807356731621525151438554207958025086371195596429",
    "29288366693964937935024238809338591846445122186193325996969951583534009804735",
    "45520918364002402195697099465067784163652370673587121791220347937985430696059",
    "30204620997498658484761557342696480462811612120292285282592046293298019225139",
    "6739722627047123650704294650168547689199576889424317598327664349670094847386",
    "12552068434669825496994804792035099139119510231229333384039699180177506330883",
    "35606355404584487039656709037031644298069022339158027123094434051470693652144",
    "27152777689832600237603832839580530431261892212012891284086158732906536564275",
    "1565358634219027857515225968469191012422290362402249429595901759266073802893",
    "18377449490291719172105316600514869953527084082702417269360255470807480422586",
    "33028539839166441775261661380446642889815534490733685107638094997616562965012",
    "41129121523443687926610854474916308032891317009466277612592777022248014480454",
    "23775038689782027882874001281753390097904495977613918721279232805531252455530",
    "49284445344648395982606460699787286188487311295683213731065377453486963801645",
    "858972874843873268243359663431678864509140619986711974845974381002122433533",
    "2284665870288710039582866064939283290838684967185794392379632680690355520999",
    "23777128127216060588640725009799439474306054792152180805932690141776117495478",
    "36940298173791853383736009856877617644423110936957833653405081816053297277912",
    "3208200230745782152590587223151995564748245009905165118452554320147381931666",
    "18718569356736340558616379408444812528964066420519677106145092918482774343613",
    "45647874064490540535102560953740992370310542221175676365363308275608388794794",
    "42374826598431294035583551589714293562804737170627894962386165496998036874648",
    "34578955982553311791661574540457431604765539406066179766618766880998114696103",
    "30615280727255154282592849141346605177237184431350125205644038998854600969543",
    "2216432659854733047132347621569505613620980842043977268828076165669557467682",
    "19538618822035560439530110642116736453888742381411961708863219190294351019531",
    "42694566063913220624109194351060406849723503477110502557725432065527856289007",
    "25925283330344843199611797281014150288211874798016351231444343582628254214478",
    "11289584652236598210366432823032912291870346397436838789653918914953082369394",
    "5414786680472503351775865880830862946896666350012919021436810911282055859083",
    "16222384601744433420585982239113457177459602187868460608565289920306145389382",
    "23460972306242747416621830726724864573082287317939789453032148116555585735677",
    "50475553482233899853997654951168849196097322910429497790738485116498852360354",
    "41337881192983337553263666219250419611470489965792898734004761590729663177163",
    "28017492901276950434510712400816836340544087390565805395002940187771096578926",
    "2113856351671110686500065221576598210228942015572754387088472024121079200325",
    "48266727765444344361988209762419593610150161046403393864549875567722358598401",
    "41485237989158755411312447675308281675437272565746354009708603079070493274143",
    "44614336439174284715200480043874668645001838161343371155481977593786367552317",
    "46921019123607277624729619499000579810984311405917826201906240223758838701862",
    "1541908893462057220150336941109365790384225557235909854552197862325429313313",
    "35452938354154164039822756808865794216250775936968891807380264948150909419541",
    "31151051080476248676447826569023414770930337641159575374357979475084729858341",
    "43949756806214856001712135212577261560390887373394764405136477029250058031464",
    "9461041459101770251462662487857689040308119625076606636828397785150854044090",
    "3165716305239792423642656184343270644019196298402995496498490496610409549069",
    "41043894167544478681722210959123939439396968723917286283548267494895562182122",
    "3311910318030562758707053344127002682021676843794212171168807941139472964018",
    "966531860221509986238738501006544301058021610982536533439610938867894666420",
    "50845701992581098098108319514456242572468719216881036156378507644076925091961",
    "50241637197424962577092408475143289727244107873275751763784617216493441118613",
    "51260629170620081370228230215321113343333416770903029594293292349161007943740",
    "32591436744806488848267881137794348994922158826692842385471321084412336721985",
    "14931067053926368974213079566796149933168044365452384215423321735417850282831",
    "32670068276315811036531795647823108986195309612443626717208893396310620787944",
    "39329813235883791664275830051443962772301854094439467762437831591807461254106",
    "7594017890037021425366623750593200398174488805473151513558919864633711506220",
    "10320499816298632021009000223924946938726883211156513342393565495695228001122",
    "48719235542044141758924767586000036310164624282036895371098877804515108298488",
];
