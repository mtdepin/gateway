

package event

import (
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"
)

type ExampleTarget struct {
	id       TargetID
	sendErr  bool
	closeErr bool
}

func (target ExampleTarget) ID() TargetID {
	return target.id
}

// Save - Sends event directly without persisting.
func (target ExampleTarget) Save(eventData Event) error {
	return target.send(eventData)
}

func (target ExampleTarget) send(eventData Event) error {
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	time.Sleep(time.Duration(b[0]) * time.Millisecond)

	if target.sendErr {
		return errors.New("send error")
	}

	return nil
}

// Send - interface compatible method does no-op.
func (target ExampleTarget) Send(eventKey string) error {
	return nil
}

func (target ExampleTarget) Close() error {
	if target.closeErr {
		return errors.New("close error")
	}

	return nil
}

func (target ExampleTarget) IsActive() (bool, error) {
	return false, errors.New("not connected to target server/service")
}

// HasQueueStore - No-Op. Added for interface compatibility
func (target ExampleTarget) HasQueueStore() bool {
	return false
}

func TestTargetListAdd(t *testing.T) {
	targetListCase1 := NewTargetList()

	targetListCase2 := NewTargetList()
	if err := targetListCase2.Add(&ExampleTarget{TargetID{"2", "testcase"}, false, false}); err != nil {
		panic(err)
	}

	targetListCase3 := NewTargetList()
	if err := targetListCase3.Add(&ExampleTarget{TargetID{"3", "testcase"}, false, false}); err != nil {
		panic(err)
	}

	testCases := []struct {
		targetList     *TargetList
		target         Target
		expectedResult []TargetID
		expectErr      bool
	}{
		{targetListCase1, &ExampleTarget{TargetID{"1", "webhook"}, false, false}, []TargetID{{"1", "webhook"}}, false},
		{targetListCase2, &ExampleTarget{TargetID{"1", "webhook"}, false, false}, []TargetID{{"2", "testcase"}, {"1", "webhook"}}, false},
		{targetListCase3, &ExampleTarget{TargetID{"3", "testcase"}, false, false}, nil, true},
	}

	for i, testCase := range testCases {
		err := testCase.targetList.Add(testCase.target)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}

		if !testCase.expectErr {
			result := testCase.targetList.List()

			if len(result) != len(testCase.expectedResult) {
				t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
			}

			for _, targetID1 := range result {
				var found bool
				for _, targetID2 := range testCase.expectedResult {
					if reflect.DeepEqual(targetID1, targetID2) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
				}
			}
		}
	}
}

func TestTargetListExists(t *testing.T) {
	targetListCase1 := NewTargetList()

	targetListCase2 := NewTargetList()
	if err := targetListCase2.Add(&ExampleTarget{TargetID{"2", "testcase"}, false, false}); err != nil {
		panic(err)
	}

	targetListCase3 := NewTargetList()
	if err := targetListCase3.Add(&ExampleTarget{TargetID{"3", "testcase"}, false, false}); err != nil {
		panic(err)
	}

	testCases := []struct {
		targetList     *TargetList
		targetID       TargetID
		expectedResult bool
	}{
		{targetListCase1, TargetID{"1", "webhook"}, false},
		{targetListCase2, TargetID{"1", "webhook"}, false},
		{targetListCase3, TargetID{"3", "testcase"}, true},
	}

	for i, testCase := range testCases {
		result := testCase.targetList.Exists(testCase.targetID)

		if result != testCase.expectedResult {
			t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestTargetListList(t *testing.T) {
	targetListCase1 := NewTargetList()

	targetListCase2 := NewTargetList()
	if err := targetListCase2.Add(&ExampleTarget{TargetID{"2", "testcase"}, false, false}); err != nil {
		panic(err)
	}

	targetListCase3 := NewTargetList()
	if err := targetListCase3.Add(&ExampleTarget{TargetID{"3", "testcase"}, false, false}); err != nil {
		panic(err)
	}
	if err := targetListCase3.Add(&ExampleTarget{TargetID{"1", "webhook"}, false, false}); err != nil {
		panic(err)
	}

	testCases := []struct {
		targetList     *TargetList
		expectedResult []TargetID
	}{
		{targetListCase1, []TargetID{}},
		{targetListCase2, []TargetID{{"2", "testcase"}}},
		{targetListCase3, []TargetID{{"3", "testcase"}, {"1", "webhook"}}},
	}

	for i, testCase := range testCases {
		result := testCase.targetList.List()

		if len(result) != len(testCase.expectedResult) {
			t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}

		for _, targetID1 := range result {
			var found bool
			for _, targetID2 := range testCase.expectedResult {
				if reflect.DeepEqual(targetID1, targetID2) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
			}
		}
	}
}

func TestTargetListSend(t *testing.T) {
	targetListCase1 := NewTargetList()

	targetListCase2 := NewTargetList()
	if err := targetListCase2.Add(&ExampleTarget{TargetID{"2", "testcase"}, false, false}); err != nil {
		panic(err)
	}

	targetListCase3 := NewTargetList()
	if err := targetListCase3.Add(&ExampleTarget{TargetID{"3", "testcase"}, false, false}); err != nil {
		panic(err)
	}

	targetListCase4 := NewTargetList()
	if err := targetListCase4.Add(&ExampleTarget{TargetID{"4", "testcase"}, true, false}); err != nil {
		panic(err)
	}

	testCases := []struct {
		targetList *TargetList
		targetID   TargetID
		expectErr  bool
	}{
		{targetListCase1, TargetID{"1", "webhook"}, false},
		{targetListCase2, TargetID{"1", "non-existent"}, false},
		{targetListCase3, TargetID{"3", "testcase"}, false},
		{targetListCase4, TargetID{"4", "testcase"}, true},
	}

	resCh := make(chan TargetIDResult)
	for i, testCase := range testCases {
		testCase.targetList.Send(Event{}, map[TargetID]struct{}{
			testCase.targetID: {},
		}, resCh)
		res := <-resCh
		expectErr := (res.Err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestNewTargetList(t *testing.T) {
	if result := NewTargetList(); result == nil {
		t.Fatalf("test: result: expected: <non-nil>, got: <nil>")
	}
}
