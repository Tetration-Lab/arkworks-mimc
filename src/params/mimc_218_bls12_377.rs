use crate::MiMCParameters;

#[derive(Debug, Clone, Default)]
pub struct MIMC_218_BLS12_377_PARAMS;

impl MiMCParameters for MIMC_218_BLS12_377_PARAMS {
    const ROUNDS: usize = 218;
    const EXPONENT: usize = 5;
}

pub const MIMC_218_BLS12_377_ROUND_KEYS: [&str; MIMC_218_BLS12_377_PARAMS::ROUNDS] = [
    "0",
    "7120861356467848435263064379192047478074060781135320967663101236819528304084",
    "3133739901812751471326494415664766472036557470026894633138154061216152011204",
    "1091427515161327441889619337150727225052604642412635746072836983750651309302",
    "2997652940524966391902291071747840929583981097001256053916864558563857236176",
    "6213034651206321099554911529432858929316916589786226278158945235122524620134",
    "6272534127525752356301651245545777202175355314690979502891502877588756273964",
    "777177528574498056858121055801659665262179837512606976146481807627199138864",
    "1871443742122864674534759643645071360176654316097591399825056123672120789974",
    "2973898558766274706255762061667048799651557405026315677601201365201782650826",
    "4798196928559910300796064665904583125427459076060519468052008159779219347957",
    "7051811365250637105984610848227995446935274706111682265891709030166663736432",
    "8114369382021161329783673095608266245487709086249709179364670006022288149265",
    "1562114885423228058170656509969756111492382304660015067577050473937003644244",
    "2991211057740448809282997402904527543859898466715882811226089688656465266519",
    "2303441850555523132712855286391930858142632812411106636133373808045153714535",
    "1792680357594567315377216275957848354021470984220580423047704341064804149854",
    "4111608475337986864173247140042543277100176123300204228871395403199131964749",
    "57223503782220515559720336039496530390086925817242587313562583323070603435",
    "1257594158588682613833204505462207260583490648969071499050497362727195898111",
    "4635031088821700182034377765061296746407719700348490765105285797923497393786",
    "5460335250544476467750619786407820181970312044774778989733662089719537884158",
    "5067499226992521663655964805371561768863822948197812260365062418009487097061",
    "1178752106949287469743898647227965672446623490456389673821794152087701001662",
    "4956149022327570717658064664333663714770004999780413893906223552226533747250",
    "7730524479658101416018374604609455926464272770710006968858035353891511885729",
    "8243815741056682257598948610416382099248929057094360249869596220094103153523",
    "6542545104828693971086737648102001138632278186852560726343743040169421443976",
    "5544799718820368933993511975978278249226178236799628356030150051596151721540",
    "6887418062527685944812023674300692058495243059031646745908367916483315085412",
    "5148243479486600038577811466011004009665975311731152468333338801527781698637",
    "1986097378925663590796429520480386357663532970688122089401620446234199608487",
    "1409123907536884643990049929787362285332231017052465147416698072943752629816",
    "4334703621152615256034022148413072678371980789835352096877873392172384852026",
    "5185133834892184007377852427336410046205836737648242031060541789193424192325",
    "4144769320246558352780591737261172907511489963810975650573703217887429086546",
    "1653271163684291824111318102237887376474017706605073465082795563216983320309",
    "1383271044600283630105069867869606982802653118387411930475469988705903408873",
    "7856565216416925574574295185141998971404363179273137904283875861817872086145",
    "6745410632962119604799318394592010194450845483518862700079921360015766217097",
    "3967872482373911523235712518287595458640885786778465958777054600654652863210",
    "8352294768865887258298158806707783398417644778872126846022498160812302397046",
    "3275496029869539419835891475572248292144668393746029012216767649223689884397",
    "2832093654883670345969792724123161241696170611611744759675180839473215203706",
    "3261365715428923472730455976573692627684282999842933011698728287197400546795",
    "4862224138267408833290166249214360752708575113783830421188689088165761404890",
    "4735150913547243651561826632589282390855754015447352573377671301706065265685",
    "309080794335036593075985245547841952476215358310740597118908050887510804940",
    "2306052752873695360877064113373747698739074668621064743904765063436058110149",
    "2457281441690050173020885716884164284467079443741871035189549581972026701673",
    "4611526115715198290127728046219806319537539607509946330586904680545778374260",
    "4668150443928752145073114466993070318029037079807803009118214061946142093534",
    "6545064306297957002139416752334741502722251869537551068239642131448768236585",
    "5203908808704813498389265425172875593837960384349653691918590736979872578408",
    "3800869428547988905408748925677579527591734762068856865825646720474884606253",
    "1425143306094680976145484036338727548145780862554616353136577030830035184619",
    "207641726136366754795956377896697837266555699822817065194714876135930744856",
    "1947264441098886661776382679843965055778935366789183063369911540527439326290",
    "4411053113871003275345585447007397241389912626427685366248300169394077223460",
    "1918518298243285626375000063182021986802887330553623981199141619085493298223",
    "2826915274241795799049521634868734576759700451101986059371502564688050284917",
    "7470438008846102280411911867211305974980455662069445206496759575806812630294",
    "3728985430710227959260974206317204379880261864973937520593270943665863713681",
    "515100310600199276795148121888807202199446058499621949039715461070624214930",
    "1056007962013359187016612868918093615164727295270424318470990990634831445597",
    "1722459393284486838157395888364408746312676027563115047723859277470066956464",
    "8327443473179334761744301768309008451162322941906921742120510244986704677004",
    "324089127944469766561103611586868654670303041259100381726684029317676622558",
    "5058261885178762937498791053630185805181547401485691676187174155287981305297",
    "7448959706054814502695963902031607284087770395261681084454318075362912497730",
    "6197762810499579741863793177379054999741147749051948938527099415631969118464",
    "6835791988337163732329540306031815301592388220275312528820568453929683484529",
    "7132325028834551397904855671244375895110341505383911719294705267624034122405",
    "148317947440800089795933930720822493695520852448386394775371401743494965187",
    "5220481165974376150890502843344335607933932459810074163206775164672710167032",
    "44385533003951699128807213685011060320504705511309319977140946167099707901",
    "881810204319744681635104380555152433810993727786202993646982920244948713658",
    "5995938818445305951927152143177383707097478418365065057718626832378220597674",
    "1163088473748575963898113130525910436466509265115484362804714084904307115708",
    "3420277532107370772448777828868041612220872620280243096156553396531779135600",
    "176061952957067086877570020242717222844908281373122372938833890096257042779",
    "6864105221127674529007541059498010233468406855640601285126177679078557603874",
    "7423311247662039466366077428789766196349730027913503122259136652328330807352",
    "7015414767382341627345543619828755232999133605565467258923324018619943468273",
    "3035689345002451858053081300295848227590245746251945843757189826209723663955",
    "4586984464321125373742030162836467550036722595445836103362032449385825752173",
    "1476796560309775385799535287861091684057603538456607275431802907222946960536",
    "474696686928104621421906190569871298986108913149100836279522165759722991980",
    "816880740024816298522025728637456092837148055234298171798106462209010797573",
    "8115872652339826846631852521558157690310931619402221860538347849626915359210",
    "4065609543475290115285326787213281835338878793091001833008564757915237347666",
    "32883284540320451295484135704808083452381176816565850047310272290579727564",
    "149429784941604461110786205143449793808745837600069741469012607464831015039",
    "7026053132628053846307552280673392034966944889974429087709303584372424832488",
    "7841521468344197781801193321534007350137506796640238850493114674837622211367",
    "2850723357319070672316951125693077604283283912287436149770807272388240490105",
    "7539406529680206120833599909376532379290396855851185322569217226342980995",
    "5358224061249821143405786250255276709033608880800951565168103421347860691101",
    "4820000669823695167199709009373156635051060350626770703723881689168704342367",
    "726289956593981949102642440772187060177102052098630515165404482378649586177",
    "2484942342995033562903454206172626807661615190358981652206226311005084520206",
    "7132367750565387617910364731890615167755990773533543342812882384351625628137",
    "1234732402861101584198921172749066898023161810534211436701071480373571613784",
    "4704944019896249388097902849324753390109690245206002624450917737358866967319",
    "7090107751541500623310186897691305073533171253009529942692064040829453159609",
    "2474899018196299061926321296932098562658436100509191787631035436201483253423",
    "5500155320378757939973552277067437719942062872123859043872653749672701785408",
    "3322573361620948336469794760947232135257754107329901896076444324206237682780",
    "6302459974440934609493112649448345986143594005693150511792490825208571195127",
    "152803254821996614079948434444529965714010140549316811306815273880404257200",
    "6697304821313867364902190601353951272354524862654422806557727640022658419616",
    "2802111336832382835745146315944066679817787348834362685945592692173402652825",
    "4683101479951853642453185627731339854826600906557705001323016339092583875758",
    "2866623693223921210573973369049884504400349592048223067271892411625061111037",
    "643882484912683016443539738999008049854637067783850588369001373953773174191",
    "792781492853909872425531014397300057232399608769451037135936617996830018501",
    "5027602491523497423798779154966735896562099398367163998686335127580757861872",
    "6150742826225945813423939885080695314034465943648850477017769481395891314531",
    "192969337837916911923982774077976031491095957979106080745115436130700010980",
    "7950601415565256298438057788260603709749410074563381553919680508757240079544",
    "3129661083692050772999065332603521797266406846221090166314282102866841619680",
    "4456679825615070013427369568157483751850837803430876197027841293379093777748",
    "837918530550013444972520070042413231385925685754625727898806936006548241403",
    "425599984420480079136859068226439386436559138491739428867724058461806103129",
    "4787333451156253107671184032507871602865280926191362000515719016051839566753",
    "3102697202279494646950933991028304003234778556307357939498402487487688751280",
    "4583598652712229473698323954093760411929471938626699523523902745808290235182",
    "5060522606891313336985831645078209073358238411026075143934964665552582780858",
    "8356406042258574812473103329534177678382454803599751428782752332456365989693",
    "1645742752184432752068884306897605799681982852257713860811563588788654171928",
    "7516580329295021161970423297472386212037654197705412735614790647149756087476",
    "2948798637446484372342543776366908308159651404768293624033402765385479179075",
    "1022049130319503314470989597705277689662863527965515419345531966465009211787",
    "5232405782912177312790945236315236324499328950787496377736211870328163769326",
    "7576448134646359515578908911661193402211269920041944625540459361524205868909",
    "6887514443234114980722172933330612320214461153537147119422791459213921241987",
    "7329619377976145893418184549576945165549981022088021844336636615869380171882",
    "5933747564228028785964752022291073910614421272083313061381121092983135563937",
    "7281426946818735803307725589852316984680438364412216382076933599510884032546",
    "445380082959623035117298304446810192750272260113934181939194934804073556215",
    "4450367275349831842597794483734772311116034234559881408657254740420302834971",
    "1566319469551337352680317000436417210434045695378607444187553275022493081328",
    "5145813514586092695040523697217130480226324273818555090285189073756953119788",
    "601763898750009063159316060517408272886019390044134099611024169648441170071",
    "7203544282989180909343689362956267219007258136241440367762580615978511251039",
    "2281547904402496072616649012982872996206510014722383715162653845487558007546",
    "5558140070304683425052376503380473486567259973755876548249912075459657862281",
    "6501659735951776535466191586529896066251671044599735288124065611292771128315",
    "4253661524771470405712752113975716743423018960310424293833137786405084977519",
    "397690828254561723549349897112473766901585444153303054845160673059519614409",
    "5936545842557296117758169835637483627958016149121099871753631534702353580704",
    "232181351986836919444098493365828880891506105276033068580904988450505908977",
    "3887471090154976028661888928302158386320268362717702547825472311603790785039",
    "8245813646057260003878900128731567534953813337952089623866735536382227552344",
    "5221207986862665209728235657036488353909923097763221042477912912582379474613",
    "2500150145735552266867296490478781254367358917178337172829217674035863879583",
    "7451023387474079745244099039260583195225562268250450842413469856932826907287",
    "2396943199947354207010680971459502834624767295810127725643973341343336165577",
    "3546477794049798125270033256397083658010099886699285878006517284075962117874",
    "814913922521637742587885320797606426167962526342166512693085292151314976633",
    "2033285157743822702137466927002665961998011981888150456601907438975111934246",
    "2158018474022695470306691216882533956300169748892262736110587714323759962121",
    "2320562795730994787512669777436862614862509015702196541976263458801429426853",
    "5915861901617520628923135931930504012625776978978034242064607850485160466208",
    "832674125848416597587364628018388566024142836192497418369879883545299622654",
    "2049141805258236626730672343057097793517876819025747065958427266605536350022",
    "3336981994307735458142908038726165206388513905979619623596379113649378002296",
    "7667427893001229216994493645658102632117678413625721042031831893727212187773",
    "3677541357802543622125251460808296740279902691914744381423655826724716965165",
    "1339262068841751254138167691973296430352803659810150971073223994071881990459",
    "7106326667241103688964924622706576021046988203521972839695604922106070143648",
    "3126561620282026389320828562178258034831100875460888782817435397247744443674",
    "1170117949355223385919105615732034496547544819573124284985089380876297331591",
    "2352169435460931651919530745940584372409991373953668239511481014866028589996",
    "2982912715980719571348157103306294504631919374131764079243816201524493801458",
    "2091192888077587768000576937942431735917303367214246002945529608917168237063",
    "1654963395071855391778363793002864910587662578745918167640086194786436599291",
    "3441779355721298617499168955503669680445005765421407679565886956952857663903",
    "1855298493690555228444144261056963190079827546579600397525336542926251677250",
    "2759625540189631267882649029152525154145356791930203463441271978227903400565",
    "7096676993846879853680989288749391854077681430485924014418309779155480132800",
    "7582951869316496224725295891818573591079915556322935658398058758776106672787",
    "407425886070714542655565806499472359111047488084944374467991735777612393450",
    "158340189692088152756008850201637984362299886226354396265267576150458509303",
    "6134280022395622953534347860009083512989026157042831896425836832715536720286",
    "6038012077774110904013246514580371737514939926631614069067606756504586257722",
    "1311692854936355960342886994298964729293432007051666462791531773604792070337",
    "6243833838435610710801867569033915301018235761640560707347245727543882402927",
    "4367135494295156966517232659249708715463521535630844428400021482750818889049",
    "374456041711896083948980218498315795597649414597817789421371505092283498657",
    "208714196059627420954614407016396601167312081293693283028734045259908187180",
    "8168829986877133934362762966303922102741798144095786227882143235593538364171",
    "7322911377099698347246217786334153138899763131296878415048254338524206931011",
    "3329569412159251748037053790409387943527330059986133093268351010792044587716",
    "3053802865630233893233749277537039884295003759684727337311945796258359555848",
    "5477918657857466221356493788284519813542169130385967027040716086527959684791",
    "7230758461393580045564499319857206430014126199289928211145425270240595766589",
    "5571677997861254554543621908219405176782313128150753173947722710835497475291",
    "2906493824987467972651280178168291397851001580385287373701667673527296213383",
    "7353715596435942347001208939735513869636518190397263605908390530903198655511",
    "1881352043397617387189668454045035745499122912944186065505870557189950525598",
    "2258349972430775017222503573186786315799834372557606343783560676413738157593",
    "8033844909328920863168048872729271468143594871968199627049694244171998169008",
    "8227259900679881719496810380207043137165700269680048553119600638182809873173",
    "8396380150533605587416543134103957213112531999200880876362713792227617522809",
    "2397396163464029474508932300786502799338833492802753086182177927431993063537",
    "1600164870516061963063576802490930386149425227486858613841126819509181241680",
    "408630612996750291355028540016898208257803961268942038983346419289615201948",
    "2861026628966596371104039737015605009001925785374925112938350117778668978835",
    "5509515809876016602318088712415908385675712235819600154841393776308142973604",
    "1936417038844547926507779649795834080575717109506956395049550160119435224600",
    "8272253310850470584306164139952805294054165439189871904368473207633880791444",
    "2182896719994496871748509248561119357625197256732003119451535150111302034016",
    "5749965066557183678067706190920583354588863075002303956486641241625834866742",
    "5783006113706995003705269059840447119993786953787211608860389517864094205216",
    "6334853268192339350804513381421197448166416257058727352853434767424855844575",
    "3383299147805690439281953956762605859045768589132463818888154677155652281485",
    "0",
];
