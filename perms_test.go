package perms

import (
	"fmt"
	"testing"
)

type User struct {
	Name        string
	IsSuperuser bool
}

type Group struct {
	Name string
	Members []string
}

type Video struct {
	Name string
	Duration float64

	Public bool
	User string
	Group string
}

type Playlist struct {
	ID string
	videos []Video

	Public bool
	User string
	Group string
}

type Archive struct {
	Name string

	User string
	Group string
}

const (
	ALLOW = "allow"
	DENY = "deny"
)

func TestAddRule(t *testing.T) {
	rs := NewRuleSet(DENY)
	rs.AddRule(&User{}, "view", &Playlist{},
		func (subj interface{}, act interface{}, res interface{}) (matches bool, effect string, quick bool) {
			user := subj.(*User)
			// if !ok {
			// 	return false, "", false
			// }
			action := act.(string)
			playlist := res.(*Playlist)
			// if !ok {
			// 	return false, "", false
			// }
			fmt.Printf("[view] user:%v action:%v playlist:%v\n", user, action, playlist)
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
	rs.AddRule(&User{}, "modify", &Playlist{},
		func (subj interface{}, act interface{}, res interface{}) (matches bool, effect string, quick bool) {
			user := subj.(*User)
			action := act.(string)
			playlist := res.(*Playlist)
			fmt.Printf("[modify] user:%v action:%v playlist:%v\n", user, action, playlist)
			if playlist.User == user.Name {
				return true, ALLOW, false
			}
			return true, DENY, false
		})
	rs.AddRule(&User{}, "view", &Video{},
		func (subj interface{}, act interface{}, res interface{}) (matches bool, effect string, quick bool) {
			user := subj.(*User)
			action := act.(string)
			video := res.(*Video)
			fmt.Printf("[view] user:%v action:%v video:%v\n", user, action, video)
			if user.IsSuperuser {
				return true, ALLOW, true
			}
			if video.Public {
				return true, ALLOW, false
			}
			if video.User == user.Name {
				return true, ALLOW, false
			}
			return true, DENY, false
		})
	rs.AddRule(&User{}, "modify", &Video{},
		func (subj interface{}, act interface{}, res interface{}) (matches bool, effect string, quick bool) {
			user := subj.(*User)
			action := act.(string)
			video := res.(*Video)
			fmt.Printf("[%v] user:%v action:%v video:%v\n", action, user, action, video)
			if user.IsSuperuser {
				return true, ALLOW, true
			}
			if video.User == user.Name {
				return true, ALLOW, false
			}
			return true, DENY, false
		})
	rs.AddRule(&Group{}, "modify", &Playlist{},
		func (subj interface{}, act interface{}, res interface{}) (matches bool, effect string, quick bool) {
			group := subj.(*Group)
			action := act.(string)
			playlist := res.(*Playlist)
			fmt.Printf("[%v] group:%v action:%v playlist:%v\n", action, group, action, playlist)
			if playlist.Group == group.Name {
				return true, ALLOW, false
			}
			return true, DENY, false
		})
	rs.AddRule(&User{}, "view", nil,
		func (subj interface{}, act interface{}, res interface{}) (matches bool, effect string, quick bool) {
			user := subj.(*User)
			action := act.(string)
			fmt.Printf("[view] user:%v action:%v resource:%v\n", user, action, res)
			if user.IsSuperuser {
				return true, ALLOW, true
			}
			return true, DENY, false
		})

	john := &User{
		Name:        "john",
		IsSuperuser: false,
	}
	jack := &User{
		Name:        "jack",
		IsSuperuser: false,
	}
	anonymous := &User{
		Name:        "anonymous",
		IsSuperuser: false,
	}
	overlord := &User{
		Name:        "overlord",
		IsSuperuser: true,
	}
	john_playlist := &Playlist{
		ID:     "6563",
		User:   "john",
		Group:  "john",
	}
	john_public_playlist := &Playlist{
		ID:     "6274",
		Public: true,
		User:   "john",
		Group:  "john",
	}
	jack_playlist := &Playlist{
		ID:     "9374",
		User:   "jack",
		Group:  "editors",
	}
	check := func(got string, want string) {
		fmt.Printf("eff: %v\n", got)
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
	check(rs.Query(john, "modify", john_playlist), ALLOW)
	check(rs.Query(john, "modify", jack_playlist), DENY)
	check(rs.Query(jack, "modify", jack_playlist), ALLOW)
	check(rs.Query(jack, "view", john_playlist), DENY)
	check(rs.Query(jack, "view", john_public_playlist), ALLOW)
	check(rs.Query(anonymous, "view", john_public_playlist), ALLOW)
	check(rs.Query(overlord, "modify", jack_playlist), DENY)
	check(rs.Query(&Group{
		Name: "editors",
	}, "modify", john_playlist), DENY)
	check(rs.Query(&Group{
		Name: "editors",
	}, "modify", jack_playlist), ALLOW)
	check(rs.Query(jack, "view", &Archive{Name: "test"}), DENY)
	check(rs.Query(overlord, "modify", &Archive{Name: "test"}), DENY)
	check(rs.Query(overlord, "view", &Archive{Name: "test"}), ALLOW)
}
