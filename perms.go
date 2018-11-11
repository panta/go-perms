// Copyright (C) 2019 Marco Pantaleoni. All rights reserved.
// Use of this source file is governed by the GNU General Public License v2.0 that
// can be found in the LICENSE.txt file.
// Commercial users can obtain a commercial license by contacting the author.

/*
	Package perms provides a simple but flexible permission control library in Golang.

	It is possible to define sets of rules where each rule is a function mapping
	a tuple (subject, action, resource) to an "effect" string, where the effect could
	be for example "allow" or "deny".

	The types of subject, action and resource are not mandated.

	For efficiency reasons, to allow processing of very large rule sets, when adding
	a rule it's possible to provide value "templates" that any or all of subject, action
	and resource must adhere to for the rule to be evaluated.

	Examples will make this much clearer :-)
 */
package perms

import (
	"fmt"
	"reflect"
)

type typ reflect.Type

type MatcherFn func (subject interface{}, action interface{}, resource interface{}) (matches bool, effect string, quick bool)
type Rule struct {
	subject interface{}
	action interface{}
	resource interface{}
	matcher MatcherFn
}
type RuleList []Rule

type RuleSet struct {
	m3rules       map[typ]map[typ]map[typ]RuleList
	DefaultEffect string
}

// NewRuleSet returns a new rule set, the context object that hold and evaluate rules.
func NewRuleSet(defaultEffect string) *RuleSet {
	return &RuleSet{
		m3rules:       make(map[typ]map[typ]map[typ]RuleList),
		DefaultEffect: defaultEffect,
	}
}

// AddRule adds a rule for the (subject, action, resource) types triple.
// Pass a nil subjectType/actionType/resourceType to specify a "jolly" for that parameter.
// Note that the matcher can inspect and decide if/how to apply the rule independently from
// subjectType, actionType and resourceType. But if these are specified (non-nil), then
// when evaluating a (subject, action, resource) tuple, its constituents must adhere to the
// provided types (and values if comparable and non-zero, eg. strings).
func (ruleSet *RuleSet) AddRule(subjectType interface{}, actionType interface{}, resourceType interface{}, matcher MatcherFn) {
	rule := Rule{
		subject: subjectType,
		action: actionType,
		resource: resourceType,
		matcher: matcher,
	}
	sT := reflect.TypeOf(subjectType)
	aT := reflect.TypeOf(actionType)
	rT := reflect.TypeOf(resourceType)

	aMap, ok := ruleSet.m3rules[sT]
	if !ok {
		aMap := map[typ]map[typ]RuleList{
			aT: map[typ]RuleList{
				rT: []Rule{rule},
			},
		}
		ruleSet.m3rules[sT] = aMap
		return
	}

	rMap, ok := aMap[aT]
	if !ok {
		rMap := map[typ]RuleList{
			rT: []Rule{rule},
		}
		aMap[aT] = rMap
		return
	}

	rMap[rT] = append(rMap[rT], rule)
}

func (ruleSet *RuleSet) findRules(subject interface{}, action interface{}, resource interface{}) RuleList {
	typeOfSubject := reflect.TypeOf(subject)
	typeOfAction := reflect.TypeOf(action)
	typeOfResource := reflect.TypeOf(resource)

	aMap, ok := ruleSet.m3rules[typeOfSubject]
	if !ok {
		return nil
	}

	rMap, ok := aMap[typeOfAction]
	if !ok {
		return nil
	}

	stringTypeOf := reflect.TypeOf("")		// cache
	rules := []Rule{}
	candidates := rMap[typeOfResource]
	for _, candidate := range candidates {
		// string subject?
		if typeOfSubject == stringTypeOf {
			s_subject := subject.(string)
			if s_subject != "" && subject != candidate.subject {
				// fmt.Printf("skipping rule %v - different subjects (%v != %v)\n", candidate, subject, candidate.subject)
				continue
			}
		}
		// comparable non-pointer subject?
		if subject != nil && typeOfSubject.Comparable() && reflect.ValueOf(subject).Kind() != reflect.Ptr {
			if reflect.ValueOf(subject).IsValid() && subject != candidate.subject {
				continue
			}
		}

		// string action?
		if typeOfAction == stringTypeOf {
			s_action := action.(string)
			if s_action != "" && action != candidate.action {
				// fmt.Printf("skipping rule %v - different actions (%v != %v)\n", candidate, action, candidate.action)
				continue
			}
		}
		// comparable non-pointer action?
		if action != nil && typeOfAction.Comparable() && reflect.ValueOf(action).Kind() != reflect.Ptr {
			if reflect.ValueOf(action).IsValid() && action != candidate.action {
				continue
			}
		}

		// string resource?
		if typeOfResource == stringTypeOf {
			s_resource := resource.(string)
			if s_resource != "" && resource != candidate.resource {
				// fmt.Printf("skipping rule %v - different resources (%v != %v)\n", candidate, resource, candidate.resource)
				continue
			}
		}
		// comparable non-pointer resource?
		if resource != nil && typeOfResource.Comparable() && reflect.ValueOf(resource).Kind() != reflect.Ptr {
			if reflect.ValueOf(resource).IsValid() && resource != candidate.resource {
				continue
			}
		}

		rules = append(rules, candidate)
	}
	return rules
}

// Query applies the permissions rules to the (subject, action, resource) triple returning
// an effect (or the default effect if no rule applies).
func (ruleSet *RuleSet) Query(subject interface{}, action interface{}, resource interface{}) string {
	fmt.Printf("QUERY subj:%v act:%v res:%v\n", subject, action, resource)
	// finalEffect := ruleSet.DefaultEffect

	// the first triple (tplSubject, tplAction, tplResource) is used to find matching matchers,
	// while the second triple (subject, action, resource) is the actual values passed to the
	// matcher functions.
	// The distinction is done to be able to pass a nil tpl* value to match with "jolly" rules.
	queryRules := func (tplSubject interface{}, tplAction interface{}, tplResource interface{},
		subject interface{}, action interface{}, resource interface{}) string {
		resultEffect := ""
		rules := ruleSet.findRules(tplSubject, tplAction, tplResource)
		for _, rule := range rules {
			matcher := rule.matcher
			if matcher == nil {
				continue
			}
			matches, effect, quick := matcher(subject, action, resource)
			if !matches {
				continue
			}

			if effect != "" {
				resultEffect = effect
				if quick {
					break
				}
			}
		}
		return resultEffect
	}

	final := queryRules(subject, action, resource, subject, action, resource)
	if final != "" {
		return final
	}

	final = queryRules(subject, action, nil, subject, action, resource)
	if final != "" {
		return final
	}
	final = queryRules(subject, nil, resource, subject, action, resource)
	if final != "" {
		return final
	}
	final = queryRules(nil, action, resource, subject, action, resource)
	if final != "" {
		return final
	}
	final = queryRules(subject, nil, nil, subject, action, resource)
	if final != "" {
		return final
	}
	final = queryRules(nil, nil, resource, subject, action, resource)
	if final != "" {
		return final
	}
	final = queryRules(nil, action, nil, subject, action, resource)
	if final != "" {
		return final
	}
	final = queryRules(nil, nil, nil, subject, action, resource)
	if final != "" {
		return final
	}

	return ruleSet.DefaultEffect
}
