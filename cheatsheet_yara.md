# Yara Cheatsheet

My notes shamelessly copied from resources below.

## Simple Command Line

Apply rule in /foo/bar/rules to all files in the current directory. Subdirectories are not scanned:  
```
yara /foo/bar/rules  .
```

Scan all files in the /foo directory and its subdirectories:  
```
yara /foo/bar/rules -r /foo
```

## Basic Rule

Basic rule layout with suggested various meta descriptors.  

```
rule specifc_name       // e.g. APT_CN_Winnti_exploit or crimeware_ZZ_RAT
{
    meta:               // suggested
        author = 
        date_created = 
        date_last_modified = 
        description = 
        filetype = 
        hash = 
        hash = 
        source = 
        TLP = 
        license = 
        min_yara_version = 
    
    strings:
        $a1 = "string type 1-1" ascii wide fullword nocase
        $a2 = "string type 1-2" 
        $a3 = "string type 1-3"

        $b1 = "string type 2-1"
        $b2 = "string type 2-2"
        $b3 = "string type 2-3"

        $c1 = "string type 3-1"
        $c2 = "string type 3-2"
        $c3 = "string type 3-3"
    
    condition:
        any of $a* or (2 of $b*) or (1 of $c*)
}
```

## Strings

- text strings are case sensitive.  
- case insensitive can be used with `nocase` option.  
- `wide` modifier can be used for UTF-16 formatting BUT not true UTF-16 support.  
- `ascii` modifier can be used for ASCII encoding (default).  
- `xor`  can be used to search for strings with a single byte xor applied to them.  
- you can combine all types. E.g. `ascii wide nocase xor`.  
- can write `xor (0x01-0xff)` for a specific range of xor bytes rather than all 255.  
- `fullword` odifier guarantees that the string will match only if it appears in the file delimited by non-alphanumeric characters.  
- use `fullword` keyword when string is short.  

## Hexadecimal Strings

 - Hexadecimal strings allow three special constructions that make them more flexible: wild-cards, jumps, and alternatives.  

### Wildcards
Wild-cards are just placeholders that you can put into the string indicating that some bytes are unknown and they should match anything.  

The placeholder character is the question mark (?).  

```
rule WildcardExample
{
    strings:
       $hex_string = { E2 34 ?? C8 A? FB }

    condition:
       $hex_string
}
```

### Jumps

Jumps can be used when the length of the content can vary or is unknown. 

```
rule JumpExample
{
        strings:
           $hex_string = { F4 23 [4-6] 62 B4 }

        condition:
           $hex_string
}
```

### Alternatives

Alternatives can give a hex option similar to a regular expression.  

```
rule AlternativesExample1
{
    strings:
       $hex_string = { F4 23 ( 62 B4 | 56 ) 45 }

    condition:
       $hex_string
}
```

## Regular Expressions

- They are defined in the same way as text strings, but enclosed in forward slashes instead of double-quotes.  
- E.g. `/([Cc]at|[Dd]og)/`.  
- can also be used in conjunction with `nocase`, `ascii`, `wide`, or `fullword`.  
- Regular expression evaluation is inherently slower than plain string matching and consumes a significant amount of memory.  

## Counting strings

The number of occurrences of each string is represented by a variable whose name is the string identifier but with a # character in place of the $ character.  

```
rule CountExample
{
    strings:
        $a = "dummy1"
        $b = "dummy2"

    condition:
        #a == 6 and #b > 10
}
```
This rule matches any file or process containing the string $a exactly six times, and more than ten occurrences of string $b.  

## File Size
- Can use bytes or append `KB` or `MB` as required.
- E.g. `filesize > 10KB`
- Don't use filesize modifier when scanning memory images.

## Offsets

The `at` modifier can be used to denote a decimal offset value (or vitual address for a running file). 

The `in` modifier allows a range to be specified.  

```
rule InExample_AtExample
{
    strings:
        $a = "dummy1"
        $b = "dummy2"
        $c = "dummy3"

    condition:
        $a in (0..100) and ($b in (100..filesize) or $c at 150)
}
```

## Conditions

Conditions are nothing more than Boolean expressions as those that can be found in all programming languages, for example in an if statement. They can contain the typical Boolean operators `and`, `or`, and `not`, and relational operators `>=`, `<=`, `<`, `>`, `==` and `!=`. Also, the arithmetic operators (`+`, `-`, `*`, `\`, `%`) and bitwise operators (`&`, `|`, `<<`, `>>`, `~`, `^`) can be used on numerical expressions.  

## Checking File Headers
- if possible for speed and accuracy check the file headers.  
- don't check file headers for memory images.  

Examples:  

PE Header
`uint16(0) == 0x5A4D`

ELF Header
`uint32(0) == 0x464c457f`

## Comments

```
/*
    This is a multi-line comment ...
*/
```

```
rule example { // this is a single line comment
```

## PE Module

The PE module allows you to create more fine-grained rules for PE files by using attributes and features of the PE file format. 

Preface fule with `import "pe"`

see [PE Module](https://yara.readthedocs.io/en/stable/modules/pe.html#pe-module)


## Math Module

The Math module allows you to calculate certain values from portions of your file and create signatures based on those results.  

Useful examples:

`math.entropy(0, filesize) >= 7`

## Rule Tips

- Don't use rules solely based on Windows APIs, this is prone to FPs.  
- don't try to match on run-time generated strings (for disk files).  
- don't put all criteria a necessary. Eg. not `all of them` but `five of them`.  


### What to match

- Mutex  
- Rare User Agents  
- Registry Keys  
- Typos  
- PDB Paths  
- GUIDs  
- Internal module names  
- Encoded or encrypted configuration strings  


Use clusters of groups (See example at start). Eg:
- unique artifacts found in malware  
- Win APIs  
- File properties and structure (sections, entropy, timestamp, filesize etc.)  

Then use these clusters to create the `condition`: 
- `any of $a* or 5 of $b* or 2 of $c*`

## Random Tips

- Run command line with -p option to increase performance on SSDs.  
- `pe.imphash() == "blah"` where `blah` needs to be lower case hex.  
- loops vs strings: strings is faster.  

## Random Rules from Kaspersky Webinar

Chinese language sameples, signed but not signed by MS, mimic legit Microsoft files by re-using their PE metainfo

```
condition:
    uint16(0) == 0x5A4D
    and filesize < 1000000
    and pe.version_info["Company Name"] contains "Microsoft" 
    and pe.number_of_signatures > 0
    and not forall i in (0..pe.number_of_signatures - 1):
        (pe.signatures[i].issuer contains "Microsoft" or pe.sigantures[i].issuer contains "Verisign")
    and pe.language(0x04 // LANG_CHINESE)
```

malware for AMD64 but compiled date before 64bit OS first released/created.  

```
condition:
    uint16(0) == 0x5A4D
    and (pe.machine == pe.MACHINE_AMD64 or pe.machine == pe.MACHINE_IA64)
    and pe.timestamp > 631155661 // 1990-01-01
    and pe.timestamp < 1072915200 // 2004-01-01
    and filesize > 2000000
```

## Resouces

[Yara Binaries](https://github.com/VirusTotal/yara/releases)
[Yara Readthedocs](https://yara.readthedocs.io/en/stable/)  
[Yara Git Repo](https://github.com/VirusTotal/yara)  
[Kaspersky Yara Webinar](https://securelist.com/yara-webinar-follow-up/96505/)  
[yaraPCAP](https://github.com/kevthehermit/YaraPcap)  
[Kaspersky Klara](https://github.com/KasperskyLab/klara)  
[YarGen](https://github.com/Neo23x0/yarGen)  