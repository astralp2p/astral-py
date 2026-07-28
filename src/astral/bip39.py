"""BIP-39: the English wordlist, entropy, mnemonics and seeds. Pure stdlib.

Layer 1: synchronous, I/O-free, and reachable with no node at all. The SDK
declares `dependencies = []`, so the 2048-word list ships as data in this file
rather than as a package, and the three derivations are `hashlib` and `secrets`
(design section 5.2).

The chain BIP-39 defines, and the three functions that are its steps::

    new_entropy(bits)     ->  16..32 bytes         entropy
    entropy_to_mnemonic() ->  12..24 words         a mnemonic
    mnemonic_to_seed()    ->  64 bytes             a BIP-39 seed

`mnemonic_to_entropy` inverts the second step and validates the checksum, which
is the whole of what makes a mnemonic self-checking: the last word carries
`len(words) / 3` bits of the SHA-256 of the entropy, so a mistyped word is
caught rather than derived from.

**The seed is the master secret.** Whoever holds it holds every key derived from
it, and the mnemonic is the seed. These functions exist so that a caller may
reach a seed without one crossing the IPC socket: the node's `bip137sig.mnemonic`
and `bip137sig.seed` ops answer the same values (verified byte for byte against
`furry-bolt`), and they take the mnemonic on the channel body and the passphrase
in the **query string**, which astrald writes to its log at the default
verbosity (`astrald/core/router.go:81`, `Infov(0, "%v routed in %v", q.Query, d)`
over an `astral.Query` that has no `String()`).

**Normalisation is not decoration.** BIP-39 requires the mnemonic and the
passphrase to be NFKD before PBKDF2 sees them, so two spellings of one passphrase
derive one seed. astral-go omits the step (`api/bip137sig/bip39.go`
`MnemonicToSeed`), so the node derives a different seed for each spelling:
verified live, passphrase `é` as U+00E9 answered
`8382db94…` where the same passphrase as U+0065 U+0301 answered `f37f8652…`,
and only the second is the seed BIP-39 defines. Every function here normalises,
and `api/bip137sig.py` normalises before it sends, so the node is fed the form
that makes its own answer standard. astral-go defect G-BIP39-NFKD.

**The wordlist is verifiable rather than trusted.** `WORDLIST_SHA256` is the
digest BIP-39 itself publishes for `english.txt`, and it is the digest of the
list at the foot of this file, one word per line with a trailing newline;
`tests/test_bip39.py` computes it. A single mistyped word is otherwise silent
and derives a wrong seed for every mnemonic that contains it.

**Word lookup is a dict, not a scan.** astral-go's `MnemonicToEntropy` calls
`slices.Index(wordlist, word)` once per word, which is a linear walk of up to
2048 entries each; `WORD_INDEX` is the same mapping, built once at import.

Faults split by which side is wrong. A **size the caller asks for** is
`BadArgument`: `new_entropy(100)` names a size BIP-39 does not define. A **value
that does not decode** is `ParseError`: an entropy length the wire type refuses,
a word outside the list, a word count BIP-39 does not define, a checksum that
fails. The split is not stylistic -- `validate_entropy` is the validator
`bip137sig.entropy` runs on **decode** as well, where the bytes came from a node
and no argument of the caller's is at fault. Both classes are `ValueError` as
well as `AstralError`, and `api/bip137sig.py` raises the same class for the same
fault so that one fault has one class whichever door it comes through.
"""

from __future__ import annotations

import hashlib
import secrets
import unicodedata
from typing import Final, Sequence

from .errors import BadArgument, BadArgumentType, ParseError

__all__ = [
    "DEFAULT_ENTROPY_BITS",
    "ENTROPY_BITS",
    "ENTROPY_SIZES",
    "PBKDF2_ROUNDS",
    "SALT_PREFIX",
    "SEED_LENGTH",
    "WORDLIST",
    "WORDLIST_SHA256",
    "WORD_BITS",
    "WORD_COUNTS",
    "WORD_INDEX",
    "entropy_to_mnemonic",
    "is_valid_mnemonic",
    "mnemonic_to_entropy",
    "mnemonic_to_seed",
    "new_entropy",
    "normalize",
    "validate_entropy",
    "words_of",
]

# --- the constants BIP-39 fixes ------------------------------------------

ENTROPY_BITS: Final[tuple[int, ...]] = (128, 160, 192, 224, 256)
"""Every entropy size BIP-39 defines, in bits. 128..256 in steps of 32."""

ENTROPY_SIZES: Final[tuple[int, ...]] = tuple(bits // 8 for bits in ENTROPY_BITS)
"""The same sizes in bytes: 16, 20, 24, 28, 32."""

WORD_COUNTS: Final[tuple[int, ...]] = tuple(
    (bits + bits // 32) // 11 for bits in ENTROPY_BITS
)
"""The mnemonic length each entropy size produces: 12, 15, 18, 21, 24."""

DEFAULT_ENTROPY_BITS: Final = 128
"""astral-go's `DefaultEntropyBits`, and what `bip137sig.new_entropy` uses when
`bits` is absent or zero. Verified live: `bip137sig.new_entropy` and
`bip137sig.new_entropy?bits=0` both answer 16 bytes."""

WORD_BITS: Final = 11
"""Bits per word. 2**11 is the wordlist length."""

SEED_LENGTH: Final = 64
"""The seed width PBKDF2 is asked for, and the only length `bip137sig.seed`
accepts on the wire."""

PBKDF2_ROUNDS: Final = 2048
"""BIP-39's iteration count. Not a tuning knob: the seed depends on it."""

SALT_PREFIX: Final = "mnemonic"
"""The salt is this prefix and then the passphrase, which is why an empty
passphrase is not an absent salt."""

_HASH: Final = "sha512"
"""The PBKDF2 PRF. HMAC-SHA512 in `hashlib.pbkdf2_hmac` terms."""


# --- entropy --------------------------------------------------------------


def new_entropy(bits: int = DEFAULT_ENTROPY_BITS) -> bytes:
    """Fresh entropy of `bits` bits, from the operating system's CSPRNG.

    `secrets.token_bytes`, which is `os.urandom`. The node's
    `bip137sig.new_entropy` answers the same shape from `crypto/rand`; this one
    keeps the bytes in this process.
    """
    if isinstance(bits, bool) or not isinstance(bits, int):
        raise BadArgumentType(f"bip39: bits must be an int, got {type(bits).__name__}")
    if bits not in ENTROPY_BITS:
        raise BadArgument(
            f"bip39: {bits} is not an entropy size; BIP-39 defines "
            f"{', '.join(str(b) for b in ENTROPY_BITS)} bits"
        )
    return secrets.token_bytes(bits // 8)


def validate_entropy(entropy: bytes | bytearray | memoryview) -> bytes:
    """The entropy, or the fault of its length.

    16 to 32 bytes in steps of 4, which is astral-go's `MinEntropyBytes`,
    `MaxEntropyBytes` and `EntropyStepBytes` and the rule `bip137sig.entropy`
    enforces on **both** encode and decode. `api/bip137sig.py` calls this on the
    wire type, so the two definitions of a legal entropy cannot drift apart.
    """
    if isinstance(entropy, str):
        raise BadArgumentType(
            "bip39: entropy is bytes, not str; `bytes.fromhex` parses a hex form"
        )
    if not isinstance(entropy, (bytes, bytearray, memoryview)):
        raise BadArgumentType(
            f"bip39: entropy must be bytes, got {type(entropy).__name__}"
        )
    data = bytes(entropy)
    if len(data) not in ENTROPY_SIZES:
        raise ParseError(
            f"bip137sig.entropy: {len(data)} bytes is not an entropy length; "
            f"BIP-39 defines {', '.join(str(n) for n in ENTROPY_SIZES)}"
        )
    return data


# --- mnemonics ------------------------------------------------------------


def normalize(text: str) -> str:
    """NFKD, which BIP-39 requires of a mnemonic and of a passphrase.

    A no-op for every word in the English list -- all 2048 are ASCII -- and not
    a no-op for a passphrase, which is arbitrary text.
    """
    if not isinstance(text, str):
        raise BadArgumentType(f"bip39: expected str, got {type(text).__name__}")
    return unicodedata.normalize("NFKD", text)


def words_of(mnemonic: str | Sequence[str]) -> list[str]:
    """The words of a mnemonic, normalised and split as the node splits them.

    A string splits on any run of whitespace and a sequence joins first, so both
    forms reach the same list: astrald's `OpSeed` runs `strings.Fields` over the
    `string16` it receives, and a sequence element that contains a space is two
    words there as well.
    """
    if isinstance(mnemonic, str):
        text = mnemonic
    else:
        parts = list(mnemonic)
        for part in parts:
            if not isinstance(part, str):
                raise BadArgumentType(
                    f"bip39: a mnemonic word must be str, got {type(part).__name__}"
                )
        text = " ".join(parts)
    return normalize(text).split()


def entropy_to_mnemonic(entropy: bytes | bytearray | memoryview) -> list[str]:
    """The mnemonic for this entropy: the entropy bits, then the checksum bits.

    `CS = ENT / 32` bits of `sha256(entropy)` are appended to the entropy, and
    the result is read 11 bits at a time as indices into the wordlist. The
    checksum is what makes the last word depend on every byte.
    """
    data = validate_entropy(entropy)
    checksum_bits = len(data) * 8 // 32
    checksum = hashlib.sha256(data).digest()[0] >> (8 - checksum_bits)
    value = (int.from_bytes(data, "big") << checksum_bits) | checksum
    count = (len(data) * 8 + checksum_bits) // WORD_BITS
    return [
        WORDLIST[(value >> (WORD_BITS * (count - 1 - position))) & (2**WORD_BITS - 1)]
        for position in range(count)
    ]


def mnemonic_to_entropy(mnemonic: str | Sequence[str]) -> bytes:
    """The entropy a mnemonic carries, with its checksum verified.

    Every failure names what failed and where, which the reference does not: the
    node answers `invalid mnemonic` for an unknown word and for a wrong checksum
    alike (verified live), and the two have different fixes.
    """
    words = words_of(mnemonic)
    if len(words) not in WORD_COUNTS:
        raise ParseError(
            f"bip39: {len(words)} words is not a mnemonic length; BIP-39 defines "
            f"{', '.join(str(n) for n in WORD_COUNTS)}"
        )

    value = 0
    for position, word in enumerate(words):
        index = WORD_INDEX.get(word)
        if index is None:
            raise ParseError(
                f"bip39: word {position + 1} ({word!r}) is not in the English "
                "wordlist"
            )
        value = (value << WORD_BITS) | index

    checksum_bits = len(words) // 3
    entropy_bits = len(words) * WORD_BITS - checksum_bits
    entropy = (value >> checksum_bits).to_bytes(entropy_bits // 8, "big")
    declared = value & (2**checksum_bits - 1)
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    if declared != expected:
        raise ParseError(
            "bip39: the mnemonic checksum does not match its words; one word is "
            "wrong or two are transposed"
        )
    return entropy


def is_valid_mnemonic(mnemonic: str | Sequence[str]) -> bool:
    """Whether `mnemonic_to_entropy` accepts this mnemonic.

    The predicate form, for a caller validating input rather than decoding it.
    A `BadArgumentType` still raises: a mnemonic of the wrong Python type is a
    caller fault and not an invalid mnemonic.
    """
    try:
        mnemonic_to_entropy(mnemonic)
    except ParseError:
        return False
    return True


# --- the seed -------------------------------------------------------------


def mnemonic_to_seed(mnemonic: str | Sequence[str], passphrase: str = "") -> bytes:
    """The 64-byte BIP-39 seed of a mnemonic under a passphrase.

    PBKDF2-HMAC-SHA512, 2048 rounds, the NFKD mnemonic as the password and
    `"mnemonic"` plus the NFKD passphrase as the salt.

    The mnemonic is validated first, which BIP-39 does not require and the node
    does (`MnemonicToSeed` calls `MnemonicToEntropy`): a local seed and a
    `bip137sig.seed` answer must agree on which mnemonics exist, or one of them
    derives from a typo.

    Verified against the published BIP-39 vectors and against `furry-bolt`: the
    all-zero entropy mnemonic answers `5eb00bbd…` with no passphrase and
    `c55257c3…` under `TREZOR`, from this function and from the node alike.
    """
    words = words_of(mnemonic)
    mnemonic_to_entropy(words)
    return hashlib.pbkdf2_hmac(
        _HASH,
        " ".join(words).encode("utf-8"),
        (SALT_PREFIX + normalize(passphrase)).encode("utf-8"),
        PBKDF2_ROUNDS,
        SEED_LENGTH,
    )


# --- the wordlist ---------------------------------------------------------
#
# The English list of BIP-39, in index order: word `n` is the value `n` of an
# 11-bit group. Order is the encoding, so the list is never sorted, filtered or
# deduplicated -- it is already sorted, and that is a property of the published
# file rather than a rule this module applies.

WORDLIST_SHA256: Final = (
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
)
"""The digest BIP-39 publishes for `english.txt`: the words below, one per line,
with a trailing newline. `tests/test_bip39.py` computes it from `WORDLIST`."""

_WORDS: Final = """\
abandon    ability    able    about    above    absent    absorb    abstract
absurd    abuse    access    accident    account    accuse    achieve    acid
acoustic    acquire    across    act    action    actor    actress    actual
adapt    add    addict    address    adjust    admit    adult    advance
advice    aerobic    affair    afford    afraid    again    age    agent
agree    ahead    aim    air    airport    aisle    alarm    album
alcohol    alert    alien    all    alley    allow    almost    alone
alpha    already    also    alter    always    amateur    amazing    among
amount    amused    analyst    anchor    ancient    anger    angle    angry
animal    ankle    announce    annual    another    answer    antenna    antique
anxiety    any    apart    apology    appear    apple    approve    april
arch    arctic    area    arena    argue    arm    armed    armor
army    around    arrange    arrest    arrive    arrow    art    artefact
artist    artwork    ask    aspect    assault    asset    assist    assume
asthma    athlete    atom    attack    attend    attitude    attract    auction
audit    august    aunt    author    auto    autumn    average    avocado
avoid    awake    aware    away    awesome    awful    awkward    axis
baby    bachelor    bacon    badge    bag    balance    balcony    ball
bamboo    banana    banner    bar    barely    bargain    barrel    base
basic    basket    battle    beach    bean    beauty    because    become
beef    before    begin    behave    behind    believe    below    belt
bench    benefit    best    betray    better    between    beyond    bicycle
bid    bike    bind    biology    bird    birth    bitter    black
blade    blame    blanket    blast    bleak    bless    blind    blood
blossom    blouse    blue    blur    blush    board    boat    body
boil    bomb    bone    bonus    book    boost    border    boring
borrow    boss    bottom    bounce    box    boy    bracket    brain
brand    brass    brave    bread    breeze    brick    bridge    brief
bright    bring    brisk    broccoli    broken    bronze    broom    brother
brown    brush    bubble    buddy    budget    buffalo    build    bulb
bulk    bullet    bundle    bunker    burden    burger    burst    bus
business    busy    butter    buyer    buzz    cabbage    cabin    cable
cactus    cage    cake    call    calm    camera    camp    can
canal    cancel    candy    cannon    canoe    canvas    canyon    capable
capital    captain    car    carbon    card    cargo    carpet    carry
cart    case    cash    casino    castle    casual    cat    catalog
catch    category    cattle    caught    cause    caution    cave    ceiling
celery    cement    census    century    cereal    certain    chair    chalk
champion    change    chaos    chapter    charge    chase    chat    cheap
check    cheese    chef    cherry    chest    chicken    chief    child
chimney    choice    choose    chronic    chuckle    chunk    churn    cigar
cinnamon    circle    citizen    city    civil    claim    clap    clarify
claw    clay    clean    clerk    clever    click    client    cliff
climb    clinic    clip    clock    clog    close    cloth    cloud
clown    club    clump    cluster    clutch    coach    coast    coconut
code    coffee    coil    coin    collect    color    column    combine
come    comfort    comic    common    company    concert    conduct    confirm
congress    connect    consider    control    convince    cook    cool    copper
copy    coral    core    corn    correct    cost    cotton    couch
country    couple    course    cousin    cover    coyote    crack    cradle
craft    cram    crane    crash    crater    crawl    crazy    cream
credit    creek    crew    cricket    crime    crisp    critic    crop
cross    crouch    crowd    crucial    cruel    cruise    crumble    crunch
crush    cry    crystal    cube    culture    cup    cupboard    curious
current    curtain    curve    cushion    custom    cute    cycle    dad
damage    damp    dance    danger    daring    dash    daughter    dawn
day    deal    debate    debris    decade    december    decide    decline
decorate    decrease    deer    defense    define    defy    degree    delay
deliver    demand    demise    denial    dentist    deny    depart    depend
deposit    depth    deputy    derive    describe    desert    design    desk
despair    destroy    detail    detect    develop    device    devote    diagram
dial    diamond    diary    dice    diesel    diet    differ    digital
dignity    dilemma    dinner    dinosaur    direct    dirt    disagree    discover
disease    dish    dismiss    disorder    display    distance    divert    divide
divorce    dizzy    doctor    document    dog    doll    dolphin    domain
donate    donkey    donor    door    dose    double    dove    draft
dragon    drama    drastic    draw    dream    dress    drift    drill
drink    drip    drive    drop    drum    dry    duck    dumb
dune    during    dust    dutch    duty    dwarf    dynamic    eager
eagle    early    earn    earth    easily    east    easy    echo
ecology    economy    edge    edit    educate    effort    egg    eight
either    elbow    elder    electric    elegant    element    elephant    elevator
elite    else    embark    embody    embrace    emerge    emotion    employ
empower    empty    enable    enact    end    endless    endorse    enemy
energy    enforce    engage    engine    enhance    enjoy    enlist    enough
enrich    enroll    ensure    enter    entire    entry    envelope    episode
equal    equip    era    erase    erode    erosion    error    erupt
escape    essay    essence    estate    eternal    ethics    evidence    evil
evoke    evolve    exact    example    excess    exchange    excite    exclude
excuse    execute    exercise    exhaust    exhibit    exile    exist    exit
exotic    expand    expect    expire    explain    expose    express    extend
extra    eye    eyebrow    fabric    face    faculty    fade    faint
faith    fall    false    fame    family    famous    fan    fancy
fantasy    farm    fashion    fat    fatal    father    fatigue    fault
favorite    feature    february    federal    fee    feed    feel    female
fence    festival    fetch    fever    few    fiber    fiction    field
figure    file    film    filter    final    find    fine    finger
finish    fire    firm    first    fiscal    fish    fit    fitness
fix    flag    flame    flash    flat    flavor    flee    flight
flip    float    flock    floor    flower    fluid    flush    fly
foam    focus    fog    foil    fold    follow    food    foot
force    forest    forget    fork    fortune    forum    forward    fossil
foster    found    fox    fragile    frame    frequent    fresh    friend
fringe    frog    front    frost    frown    frozen    fruit    fuel
fun    funny    furnace    fury    future    gadget    gain    galaxy
gallery    game    gap    garage    garbage    garden    garlic    garment
gas    gasp    gate    gather    gauge    gaze    general    genius
genre    gentle    genuine    gesture    ghost    giant    gift    giggle
ginger    giraffe    girl    give    glad    glance    glare    glass
glide    glimpse    globe    gloom    glory    glove    glow    glue
goat    goddess    gold    good    goose    gorilla    gospel    gossip
govern    gown    grab    grace    grain    grant    grape    grass
gravity    great    green    grid    grief    grit    grocery    group
grow    grunt    guard    guess    guide    guilt    guitar    gun
gym    habit    hair    half    hammer    hamster    hand    happy
harbor    hard    harsh    harvest    hat    have    hawk    hazard
head    health    heart    heavy    hedgehog    height    hello    helmet
help    hen    hero    hidden    high    hill    hint    hip
hire    history    hobby    hockey    hold    hole    holiday    hollow
home    honey    hood    hope    horn    horror    horse    hospital
host    hotel    hour    hover    hub    huge    human    humble
humor    hundred    hungry    hunt    hurdle    hurry    hurt    husband
hybrid    ice    icon    idea    identify    idle    ignore    ill
illegal    illness    image    imitate    immense    immune    impact    impose
improve    impulse    inch    include    income    increase    index    indicate
indoor    industry    infant    inflict    inform    inhale    inherit    initial
inject    injury    inmate    inner    innocent    input    inquiry    insane
insect    inside    inspire    install    intact    interest    into    invest
invite    involve    iron    island    isolate    issue    item    ivory
jacket    jaguar    jar    jazz    jealous    jeans    jelly    jewel
job    join    joke    journey    joy    judge    juice    jump
jungle    junior    junk    just    kangaroo    keen    keep    ketchup
key    kick    kid    kidney    kind    kingdom    kiss    kit
kitchen    kite    kitten    kiwi    knee    knife    knock    know
lab    label    labor    ladder    lady    lake    lamp    language
laptop    large    later    latin    laugh    laundry    lava    law
lawn    lawsuit    layer    lazy    leader    leaf    learn    leave
lecture    left    leg    legal    legend    leisure    lemon    lend
length    lens    leopard    lesson    letter    level    liar    liberty
library    license    life    lift    light    like    limb    limit
link    lion    liquid    list    little    live    lizard    load
loan    lobster    local    lock    logic    lonely    long    loop
lottery    loud    lounge    love    loyal    lucky    luggage    lumber
lunar    lunch    luxury    lyrics    machine    mad    magic    magnet
maid    mail    main    major    make    mammal    man    manage
mandate    mango    mansion    manual    maple    marble    march    margin
marine    market    marriage    mask    mass    master    match    material
math    matrix    matter    maximum    maze    meadow    mean    measure
meat    mechanic    medal    media    melody    melt    member    memory
mention    menu    mercy    merge    merit    merry    mesh    message
metal    method    middle    midnight    milk    million    mimic    mind
minimum    minor    minute    miracle    mirror    misery    miss    mistake
mix    mixed    mixture    mobile    model    modify    mom    moment
monitor    monkey    monster    month    moon    moral    more    morning
mosquito    mother    motion    motor    mountain    mouse    move    movie
much    muffin    mule    multiply    muscle    museum    mushroom    music
must    mutual    myself    mystery    myth    naive    name    napkin
narrow    nasty    nation    nature    near    neck    need    negative
neglect    neither    nephew    nerve    nest    net    network    neutral
never    news    next    nice    night    noble    noise    nominee
noodle    normal    north    nose    notable    note    nothing    notice
novel    now    nuclear    number    nurse    nut    oak    obey
object    oblige    obscure    observe    obtain    obvious    occur    ocean
october    odor    off    offer    office    often    oil    okay
old    olive    olympic    omit    once    one    onion    online
only    open    opera    opinion    oppose    option    orange    orbit
orchard    order    ordinary    organ    orient    original    orphan    ostrich
other    outdoor    outer    output    outside    oval    oven    over
own    owner    oxygen    oyster    ozone    pact    paddle    page
pair    palace    palm    panda    panel    panic    panther    paper
parade    parent    park    parrot    party    pass    patch    path
patient    patrol    pattern    pause    pave    payment    peace    peanut
pear    peasant    pelican    pen    penalty    pencil    people    pepper
perfect    permit    person    pet    phone    photo    phrase    physical
piano    picnic    picture    piece    pig    pigeon    pill    pilot
pink    pioneer    pipe    pistol    pitch    pizza    place    planet
plastic    plate    play    please    pledge    pluck    plug    plunge
poem    poet    point    polar    pole    police    pond    pony
pool    popular    portion    position    possible    post    potato    pottery
poverty    powder    power    practice    praise    predict    prefer    prepare
present    pretty    prevent    price    pride    primary    print    priority
prison    private    prize    problem    process    produce    profit    program
project    promote    proof    property    prosper    protect    proud    provide
public    pudding    pull    pulp    pulse    pumpkin    punch    pupil
puppy    purchase    purity    purpose    purse    push    put    puzzle
pyramid    quality    quantum    quarter    question    quick    quit    quiz
quote    rabbit    raccoon    race    rack    radar    radio    rail
rain    raise    rally    ramp    ranch    random    range    rapid
rare    rate    rather    raven    raw    razor    ready    real
reason    rebel    rebuild    recall    receive    recipe    record    recycle
reduce    reflect    reform    refuse    region    regret    regular    reject
relax    release    relief    rely    remain    remember    remind    remove
render    renew    rent    reopen    repair    repeat    replace    report
require    rescue    resemble    resist    resource    response    result    retire
retreat    return    reunion    reveal    review    reward    rhythm    rib
ribbon    rice    rich    ride    ridge    rifle    right    rigid
ring    riot    ripple    risk    ritual    rival    river    road
roast    robot    robust    rocket    romance    roof    rookie    room
rose    rotate    rough    round    route    royal    rubber    rude
rug    rule    run    runway    rural    sad    saddle    sadness
safe    sail    salad    salmon    salon    salt    salute    same
sample    sand    satisfy    satoshi    sauce    sausage    save    say
scale    scan    scare    scatter    scene    scheme    school    science
scissors    scorpion    scout    scrap    screen    script    scrub    sea
search    season    seat    second    secret    section    security    seed
seek    segment    select    sell    seminar    senior    sense    sentence
series    service    session    settle    setup    seven    shadow    shaft
shallow    share    shed    shell    sheriff    shield    shift    shine
ship    shiver    shock    shoe    shoot    shop    short    shoulder
shove    shrimp    shrug    shuffle    shy    sibling    sick    side
siege    sight    sign    silent    silk    silly    silver    similar
simple    since    sing    siren    sister    situate    six    size
skate    sketch    ski    skill    skin    skirt    skull    slab
slam    sleep    slender    slice    slide    slight    slim    slogan
slot    slow    slush    small    smart    smile    smoke    smooth
snack    snake    snap    sniff    snow    soap    soccer    social
sock    soda    soft    solar    soldier    solid    solution    solve
someone    song    soon    sorry    sort    soul    sound    soup
source    south    space    spare    spatial    spawn    speak    special
speed    spell    spend    sphere    spice    spider    spike    spin
spirit    split    spoil    sponsor    spoon    sport    spot    spray
spread    spring    spy    square    squeeze    squirrel    stable    stadium
staff    stage    stairs    stamp    stand    start    state    stay
steak    steel    stem    step    stereo    stick    still    sting
stock    stomach    stone    stool    story    stove    strategy    street
strike    strong    struggle    student    stuff    stumble    style    subject
submit    subway    success    such    sudden    suffer    sugar    suggest
suit    summer    sun    sunny    sunset    super    supply    supreme
sure    surface    surge    surprise    surround    survey    suspect    sustain
swallow    swamp    swap    swarm    swear    sweet    swift    swim
swing    switch    sword    symbol    symptom    syrup    system    table
tackle    tag    tail    talent    talk    tank    tape    target
task    taste    tattoo    taxi    teach    team    tell    ten
tenant    tennis    tent    term    test    text    thank    that
theme    then    theory    there    they    thing    this    thought
three    thrive    throw    thumb    thunder    ticket    tide    tiger
tilt    timber    time    tiny    tip    tired    tissue    title
toast    tobacco    today    toddler    toe    together    toilet    token
tomato    tomorrow    tone    tongue    tonight    tool    tooth    top
topic    topple    torch    tornado    tortoise    toss    total    tourist
toward    tower    town    toy    track    trade    traffic    tragic
train    transfer    trap    trash    travel    tray    treat    tree
trend    trial    tribe    trick    trigger    trim    trip    trophy
trouble    truck    true    truly    trumpet    trust    truth    try
tube    tuition    tumble    tuna    tunnel    turkey    turn    turtle
twelve    twenty    twice    twin    twist    two    type    typical
ugly    umbrella    unable    unaware    uncle    uncover    under    undo
unfair    unfold    unhappy    uniform    unique    unit    universe    unknown
unlock    until    unusual    unveil    update    upgrade    uphold    upon
upper    upset    urban    urge    usage    use    used    useful
useless    usual    utility    vacant    vacuum    vague    valid    valley
valve    van    vanish    vapor    various    vast    vault    vehicle
velvet    vendor    venture    venue    verb    verify    version    very
vessel    veteran    viable    vibrant    vicious    victory    video    view
village    vintage    violin    virtual    virus    visa    visit    visual
vital    vivid    vocal    voice    void    volcano    volume    vote
voyage    wage    wagon    wait    walk    wall    walnut    want
warfare    warm    warrior    wash    wasp    waste    water    wave
way    wealth    weapon    wear    weasel    weather    web    wedding
weekend    weird    welcome    west    wet    whale    what    wheat
wheel    when    where    whip    whisper    wide    width    wife
wild    will    win    window    wine    wing    wink    winner
winter    wire    wisdom    wise    wish    witness    wolf    woman
wonder    wood    wool    word    work    world    worry    worth
wrap    wreck    wrestle    wrist    write    wrong    yard    year
yellow    you    young    youth    zebra    zero    zone    zoo
"""

WORDLIST: Final[tuple[str, ...]] = tuple(_WORDS.split())
"""The 2048 words, in index order."""

WORD_INDEX: Final[dict[str, int]] = {
    word: index for index, word in enumerate(WORDLIST)
}
"""Word to index, for the lookup `mnemonic_to_entropy` does once per word."""

if len(WORDLIST) != 2**WORD_BITS:  # pragma: no cover -- a corrupted source file
    raise ParseError(
        f"bip39: the wordlist holds {len(WORDLIST)} words, not {2**WORD_BITS}"
    )
