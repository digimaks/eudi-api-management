package api

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestFlowMapping(t *testing.T) {
	cases := []struct {
		name    string
		apiFlow string
		want    string
		wantErr bool
	}{
		{name: "default empty maps to cross_device", apiFlow: "", want: "cross_device"},
		{name: "cross_device passes through", apiFlow: "cross_device", want: "cross_device"},
		{name: "same_device passes through", apiFlow: "same_device", want: "same_device"},
		{name: "dc_api maps to dcapi", apiFlow: "dc_api", want: "dcapi"},
		{name: "unknown flow errors", apiFlow: "bogus", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FlowToDB(tc.apiFlow)
			if tc.wantErr {
				qt.Check(t, qt.ErrorIs(err, ErrUnknownFlow))
				return
			}
			qt.Check(t, qt.IsNil(err))
			qt.Check(t, qt.Equals(got, tc.want))
		})
	}
}

func TestFlowFromDB(t *testing.T) {
	qt.Check(t, qt.Equals(FlowFromDB("dcapi"), "dc_api"))
	qt.Check(t, qt.Equals(FlowFromDB("cross_device"), "cross_device"))
	qt.Check(t, qt.Equals(FlowFromDB("same_device"), "same_device"))
}
