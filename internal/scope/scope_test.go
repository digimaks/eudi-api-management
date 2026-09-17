package scope

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	dcql "github.com/gmb-eudi/go-dcql"
	"github.com/go-quicktest/qt"

	"github.com/dativa-lv/eudi-api-management/internal/registrydb"
)

// mdocNS is the fixed mdoc namespace used by every test query/registration
// below — mdoc claim paths are exactly [namespace, element], both strings
// ([OID4VP §7.2] / Annex B.2.3), so every path here carries it.
const mdocNS = "org.iso.18013.5.1"

// mdocQuery builds a minimal valid single-credential mso_mdoc DCQL query
// requesting one claim path per element in elements (namespace fixed to
// mdocNS).
func mdocQuery(doctype string, elements ...string) []byte {
	var claims strings.Builder
	claims.WriteString("[")
	for i, e := range elements {
		if i > 0 {
			claims.WriteString(",")
		}
		claims.WriteString(`{"path":["` + mdocNS + `","` + e + `"]}`)
	}
	claims.WriteString("]")
	return []byte(`{"credentials":[{"id":"cred1","format":"mso_mdoc","meta":{"doctype_value":"` + doctype + `"},"claims":` + claims.String() + `}]}`)
}

// mdocClaim is the registrydb wire-shape claim path ([namespace, element])
// matching one query claim built by mdocQuery.
func mdocClaim(element string) []any { return []any{mdocNS, element} }

func mdocIntendedUse(intendedUseID, doctype string, allClaims bool, claims [][]any) registrydb.IntendedUse {
	return registrydb.IntendedUse{
		ID:            "iu-row-1",
		IntendedUseID: intendedUseID,
		Credentials: []registrydb.RegisteredCredentialJSON{
			{
				Format:         dcql.FormatMdoc,
				DoctypesOrVCTs: []string{doctype},
				AllClaims:      allClaims,
				Claims:         claims,
			},
		},
	}
}

func TestCheckWithinScope_InScopePasses(t *testing.T) {
	ius := []registrydb.IntendedUse{
		mdocIntendedUse("iu-1", "org.iso.18013.5.1.mDL", false, [][]any{
			mdocClaim("given_name"), mdocClaim("family_name"),
		}),
	}
	q, err := CheckWithinScope(mdocQuery("org.iso.18013.5.1.mDL", "given_name"), ius, "iu-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(q))
}

func TestCheckWithinScope_UnregisteredDoctype(t *testing.T) {
	ius := []registrydb.IntendedUse{
		mdocIntendedUse("iu-1", "org.iso.18013.5.1.mDL", false, [][]any{mdocClaim("given_name")}),
	}
	_, err := CheckWithinScope(mdocQuery("org.iso.18013.5.1.SOME_OTHER", "given_name"), ius, "iu-1")
	qt.Assert(t, qt.IsNotNil(err))

	var scopeErr *ScopeError
	qt.Assert(t, qt.IsTrue(errors.As(err, &scopeErr)))
	qt.Assert(t, qt.HasLen(scopeErr.Offending, 1))
	qt.Check(t, qt.StringContains(scopeErr.Offending[0], "credentials[0](cred1)"))
	qt.Check(t, qt.StringContains(scopeErr.Offending[0], "format/doctype/vct not registered"))
}

func TestCheckWithinScope_ClaimOutsideRegisteredSet(t *testing.T) {
	ius := []registrydb.IntendedUse{
		mdocIntendedUse("iu-1", "org.iso.18013.5.1.mDL", false, [][]any{mdocClaim("given_name")}),
	}
	_, err := CheckWithinScope(mdocQuery("org.iso.18013.5.1.mDL", "given_name", "document_number"), ius, "iu-1")
	qt.Assert(t, qt.IsNotNil(err))

	var scopeErr *ScopeError
	qt.Assert(t, qt.IsTrue(errors.As(err, &scopeErr)))
	qt.Assert(t, qt.HasLen(scopeErr.Offending, 1))
	// go-dcql's offense embeds the offending claim's own JSON path string —
	// never a value.
	qt.Check(t, qt.StringContains(scopeErr.Offending[0], `["org.iso.18013.5.1","document_number"]`))
}

func TestCheckWithinScope_AllClaimsCoversEverything(t *testing.T) {
	ius := []registrydb.IntendedUse{
		mdocIntendedUse("iu-1", "org.iso.18013.5.1.mDL", true, nil),
	}
	q, err := CheckWithinScope(mdocQuery("org.iso.18013.5.1.mDL", "given_name", "document_number", "portrait"), ius, "iu-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(q))
}

func TestCheckWithinScope_MalformedDCQL_IsErrInvalid(t *testing.T) {
	ius := []registrydb.IntendedUse{
		mdocIntendedUse("iu-1", "org.iso.18013.5.1.mDL", true, nil),
	}
	// Parses fine (a JSON object with a "credentials" member) but fails
	// semantic Validate: an empty credentials array ([OID4VP §6]).
	_, err := CheckWithinScope([]byte(`{"credentials":[]}`), ius, "iu-1")
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsTrue(errors.Is(err, dcql.ErrInvalid)))
}

func TestCheckWithinScope_UnparseableDCQL_IsErrParse(t *testing.T) {
	ius := []registrydb.IntendedUse{
		mdocIntendedUse("iu-1", "org.iso.18013.5.1.mDL", true, nil),
	}
	_, err := CheckWithinScope([]byte(`{`), ius, "iu-1")
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsTrue(errors.Is(err, dcql.ErrParse)))
}

// TestToClaimPaths_Conversion exercises the RegisteredCredentialJSON.Claims
// ([][]any) -> []dcql.ClaimPath conversion directly: a key, a wildcard (JSON
// null), and an index (float64, the encoding/json default) in one path,
// reconciled against go-dcql's Key/Index/Wildcard.
func TestToClaimPaths_Conversion(t *testing.T) {
	got, err := toClaimPaths([][]any{
		{"a", nil, float64(2)},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(got, 1))

	want := dcql.NewPath(dcql.Key("a"), dcql.Wildcard(), dcql.Index(2))
	qt.Check(t, qt.IsTrue(got[0].Equal(want)))
}

func TestToClaimPaths_JSONNumberVariant(t *testing.T) {
	got, err := toClaimPaths([][]any{
		{"b", json.Number("3")},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(got, 1))

	want := dcql.NewPath(dcql.Key("b"), dcql.Index(3))
	qt.Check(t, qt.IsTrue(got[0].Equal(want)))
}

func TestToClaimPaths_UnsupportedElement(t *testing.T) {
	_, err := toClaimPaths([][]any{
		{true},
	})
	qt.Assert(t, qt.IsNotNil(err))
}

func TestCheckWithinScope_UnknownIntendedUseID(t *testing.T) {
	ius := []registrydb.IntendedUse{
		mdocIntendedUse("iu-1", "org.iso.18013.5.1.mDL", true, nil),
	}
	_, err := CheckWithinScope(mdocQuery("org.iso.18013.5.1.mDL", "given_name"), ius, "iu-does-not-exist")
	qt.Assert(t, qt.IsNotNil(err))
}
