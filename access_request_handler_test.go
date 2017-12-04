package fosite_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewAccessRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	client := internal.NewMockClient(ctrl)
	handler := internal.NewMockTokenEndpointHandler(ctrl)
	hasher := internal.NewMockHasher(ctrl)
	defer ctrl.Finish()

	fosite := &Fosite{Store: store, Hasher: hasher}
	for k, c := range []struct {
		header    http.Header
		form      url.Values
		mock      func()
		method    string
		expectErr error
		expect    *AccessRequest
		handlers  TokenEndpointHandlers
	}{
		{
			header:    http.Header{},
			expectErr: ErrInvalidRequest,
			method:    "POST",
			mock:      func() {},
		},
		{
			header: http.Header{},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock:      func() {},
			expectErr: ErrInvalidRequest,
		},
		{
			header: http.Header{},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
				"client_id":  {"foo"},
			},
			expectErr: ErrInvalidRequest,
			mock:      func() {},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(nil, errors.New(""))
			},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "GET",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidRequest,
			mock:      func() {},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(nil, errors.New(""))
			},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("foo"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(errors.New(""))
			},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrServerError,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("foo"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			handlers: TokenEndpointHandlers{handler},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("foo"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(true)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
		},
		{
			//Test an URL escaped client id in basic auth
			header: http.Header{
				"Authorization": {basicAuth("f+oo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("f oo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("bar"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("bar")), gomock.Eq([]byte("bar"))).Return(nil)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
		},
		{
			//Test an non-URL escaped secret in basic auth. The secret literally has a
			//"+" sign, so when it is url unescaped, it becomes " " and the original
			//comparison will fail. Then because the before and after url unescaped strings
			//are different, it will enter the second comparison with the original secret.
			header: http.Header{
				"Authorization": {basicAuth("f+oo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"f+oo"},
			},
			mock: func() {
				firstCall := store.EXPECT().GetClient(gomock.Any(), gomock.Eq("f oo")).Return(client, errors.New("not found"))
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("f+oo")).Return(client, nil).After(firstCall)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("bar"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("bar")), gomock.Eq([]byte("bar"))).Return(nil)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessRequest{
				GrantTypes: Arguments{"f+oo"},
				Request: Request{
					Client: client,
				},
			},
		},
		{
			//Test an URL escaped secret in basic auth
			header: http.Header{
				"Authorization": {basicAuth("foo", "+bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte(" bar"))
				hasher.EXPECT().Compare(gomock.Eq([]byte(" bar")), gomock.Eq([]byte(" bar"))).Return(nil)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
		},
		{
			//Test an non-URL escaped secret in basic auth. The secret literally has a
			//"+" sign, so when it is url unescaped, it becomes " " and the original
			//comparison will fail. Then because the before and after url unescaped strings
			//are different, it will enter the second comparison with the original secret.
			header: http.Header{
				"Authorization": {basicAuth("foo", "+bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("+bar")).AnyTimes()
				firstCall := hasher.EXPECT().Compare(gomock.Eq([]byte("+bar")), gomock.Eq([]byte(" bar"))).Return(errors.New("hi"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("+bar")), gomock.Eq([]byte("+bar"))).Return(nil).After(firstCall)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
		},
	} {
		r := &http.Request{
			Header:   c.header,
			PostForm: c.form,
			Form:     c.form,
			Method:   c.method,
		}
		c.mock()
		ctx := NewContext()
		fosite.TokenEndpointHandlers = c.handlers
		ar, err := fosite.NewAccessRequest(ctx, r, new(DefaultSession))
		assert.True(t, errors.Cause(err) == c.expectErr, "%d\nwant: %s \ngot: %s", k, c.expectErr, err)
		if err != nil {
			t.Logf("Error occured: %v", err)
		} else {
			AssertObjectKeysEqual(t, c.expect, ar, "GrantTypes", "Client")
			assert.NotNil(t, ar.GetRequestedAt())
		}
		t.Logf("Passed test case %d", k)
	}
}

func basicAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
}
