# go-perms

## Overview

go-perms provides a simple but flexible permission control library in Golang.

It is possible to define sets of rules where each rule is a function mapping
a tuple `(subject, action, resource)` to an "effect" string, where the effect could
be for example `"allow"` or `"deny"`.

The types of subject, action and resource are not mandated.

For efficiency reasons, to allow processing of very large rule sets, when adding
a rule it's possible to provide value "templates" that any or all of subject, action
and resource must adhere to for the rule to be evaluated.

Examples will make this much clearer :-)

## Install

```shell
$ go get -u github.com/panta/go-perms
```

## Usage

Feel free to look at the unit tests for more extensive examples.

```go
type User struct {
	Name        string
	IsSuperuser bool
}

type Group struct {
	Name string
}

type Playlist struct {
	Public bool
	User string
	Group string
}

const (
	ALLOW = "allow"
	DENY = "deny"
)

// create a ruleset, with default DENY
rs := NewRuleSet(DENY)

// we are specifying the type templates for subject, action and resource, so the rule function callback
// will be invoked only if the types (and value for action) match, so no need to check for correct
// types here
rs.AddRule(&User{}, "view", &Playlist{},
    func (subj interface{}, act interface{}, res interface{}) (matches bool, effect string, quick bool) {
        user := subj.(*User)
        action := act.(string)
        playlist := res.(*Playlist)
        if user.IsSuperuser {
            return true, ALLOW, true
        }
        if playlist.Public {
            return true, ALLOW, false
        }
        if playlist.User == user.Name {
            return true, ALLOW, false
        }
        return true, DENY, false
    })

rs.AddRule(&Group{}, "edit", &Playlist{},
    func (subj interface{}, act interface{}, res interface{}) (matches bool, effect string, quick bool) {
        group := subj.(*Group)
        action := act.(string)
        playlist := res.(*Playlist)
        if playlist.Group == group.Name {
            return true, ALLOW, false
        }
        return true, DENY, false
    })

// when one of the subject, action, resource "templates" is nil, it matches every type/value
rs.AddRule(&User{}, "view", nil,
    func (subj interface{}, act interface{}, res interface{}) (matches bool, effect string, quick bool) {
        user := subj.(*User)
        action := act.(string)
        if user.IsSuperuser {
            return true, ALLOW, true
        }
        return true, DENY, false
    })

...

rs.Query(&User{ Name: "jack" }, "view", &Playlist{ User: "jack "})                      // -> "allow"
rs.Query(&User{ Name: "john" }, "view", &Playlist{ User: "jack "})                      // -> "deny"
rs.Query(&User{ Name: "john" }, "view", &Playlist{ Public: true, User: "jack "})        // -> "allow"
rs.Query(&User{ Name: "super", IsSuperuser: true }, "view", &Playlist{ User: "mike "})  // -> "allow"

rs.Query(&Group{ Name: "editors" }, "edit", &Playlist{ Group: "editors "})              // -> "allow"
```

## Author

* Marco Pantaleoni <marco - at - gmail.com>

## License

See the `LICENSE.txt` file.
