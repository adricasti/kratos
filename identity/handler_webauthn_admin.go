// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"cmp"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"

	"github.com/ory/herodot"
	"github.com/ory/kratos/x"
	"github.com/ory/x/jsonx"
	"github.com/ory/x/randx"
)

// adminWebAuthnUser implements webauthn.User for Admin API operations.
// Defined locally to avoid circular imports with the webauthnx package.
type adminWebAuthnUser struct {
	name        string
	id          []byte
	credentials []webauthn.Credential
	config      *webauthn.Config
}

func (u *adminWebAuthnUser) WebAuthnID() []byte   { return u.id }
func (u *adminWebAuthnUser) WebAuthnName() string { return cmp.Or(u.name, u.config.RPDisplayName) }
func (u *adminWebAuthnUser) WebAuthnDisplayName() string {
	return cmp.Or(u.name, u.config.RPDisplayName)
}
func (u *adminWebAuthnUser) WebAuthnIcon() string                       { return "" }
func (u *adminWebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// pendingWebAuthnRegistration stores session data while a WebAuthn registration
// is in progress (between options generation and credential completion).
type pendingWebAuthnRegistration struct {
	IdentityID  uuid.UUID             `json:"-"`
	SessionData *webauthn.SessionData `json:"session_data"`
	UserHandle  []byte                `json:"user_handle"`
	CreatedAt   time.Time             `json:"created_at"`
}

// pendingWebAuthnRegistrations is an in-memory store for pending registrations.
// In production, this should be persisted to the database with a TTL.
var (
	pendingRegistrations     = make(map[uuid.UUID]*pendingWebAuthnRegistration)
	pendingRegistrationsLock sync.Mutex
)

// WebAuthn Registration Options Request
//
// swagger:model adminCreateWebAuthnRegistrationOptionsBody
type AdminCreateWebAuthnRegistrationOptionsBody struct {
	// Attestation conveyance preference. Can be "none", "indirect", or "direct".
	// Default: "none"
	Attestation string `json:"attestation,omitempty"`

	// Timeout for the registration ceremony in a Go duration string (e.g. "5m", "24h").
	// Default: "5m"
	Timeout string `json:"timeout,omitempty"`

	// Authenticator attachment. Can be "platform" or "cross-platform".
	// Default: "cross-platform"
	AuthenticatorAttachment string `json:"authenticator_attachment,omitempty"`

	// User verification requirement. Can be "required", "preferred", or "discouraged".
	// Default: "required"
	UserVerification string `json:"user_verification,omitempty"`

	// Display name for the credential. If empty, uses identity traits.
	DisplayName string `json:"display_name,omitempty"`
}

// WebAuthn Registration Options Response
//
// swagger:model adminWebAuthnRegistrationOptionsResponse
type AdminWebAuthnRegistrationOptionsResponse struct {
	// The registration ID to reference this registration when completing it.
	RegistrationID uuid.UUID `json:"registration_id"`

	// The PublicKeyCredentialCreationOptions to pass to navigator.credentials.create() or a CTAP client.
	CredentialCreationOptions *protocol.CredentialCreation `json:"credential_creation_options"`
}

// WebAuthn Registration Complete Request
//
// swagger:model adminCompleteWebAuthnRegistrationBody
type AdminCompleteWebAuthnRegistrationBody struct {
	// The registration ID returned from the registration-options endpoint.
	//
	// required: true
	RegistrationID uuid.UUID `json:"registration_id"`

	// The credential creation response from the authenticator (the JSON from navigator.credentials.create()
	// or the equivalent CTAP response). This is the full PublicKeyCredential response object.
	//
	// required: true
	CredentialCreationResponse json.RawMessage `json:"credential_creation_response"`
}

// WebAuthn Registration Complete Response
//
// swagger:model adminWebAuthnRegistrationCompleteResponse
type AdminWebAuthnRegistrationCompleteResponse struct {
	// The credential ID of the newly registered credential (hex encoded).
	CredentialID string `json:"credential_id"`

	// Status of the registration.
	Status string `json:"status"`
}

// swagger:route POST /admin/identities/{id}/webauthn/registration-options identity adminCreateWebAuthnRegistrationOptions
//
// # Generate WebAuthn Registration Options
//
// Generate WebAuthn registration options (PublicKeyCredentialCreationOptions) for an identity.
// These options can be passed to a browser's navigator.credentials.create() or to an offline CTAP tool.
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
//	Schemes: http, https
//
//	Security:
//	  oryAccessToken:
//
//	Responses:
//	  200: adminWebAuthnRegistrationOptionsResponse
//	  400: errorGeneric
//	  404: errorGeneric
//	  default: errorGeneric
func (h *Handler) createWebAuthnRegistrationOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identityID := x.ParseUUID(r.PathValue("id"))

	// Load the identity to get traits for display name
	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(ctx, identityID)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var body AdminCreateWebAuthnRegistrationOptionsBody
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&body); err != nil {
		// Allow empty body (all defaults)
		if err.Error() != "EOF" {
			h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest.WithError(err.Error())))
			return
		}
	}

	// Build WebAuthn config from Kratos passkey config, then override with request parameters
	baseConfig := h.r.Config().PasskeyConfig(ctx)
	webAuthnConfig := &webauthn.Config{
		RPDisplayName: baseConfig.RPDisplayName,
		RPID:          baseConfig.RPID,
		RPOrigins:     baseConfig.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: boolPtr(true),
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationRequired,
		},
		AttestationPreference: protocol.ConveyancePreference(coalesce(body.Attestation, "none")),
		EncodeUserIDAsString:  false,
	}

	// Override authenticator attachment
	attachment := coalesce(body.AuthenticatorAttachment, "cross-platform")
	if attachment != "" {
		webAuthnConfig.AuthenticatorSelection.AuthenticatorAttachment = protocol.AuthenticatorAttachment(attachment)
	}

	// Override user verification
	if body.UserVerification != "" {
		webAuthnConfig.AuthenticatorSelection.UserVerification = protocol.UserVerificationRequirement(body.UserVerification)
	}

	// Parse and apply timeout
	if body.Timeout != "" {
		timeout, err := time.ParseDuration(body.Timeout)
		if err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(
				herodot.ErrBadRequest.WithReasonf("Invalid timeout format: %s", err)))
			return
		}
		webAuthnConfig.Timeouts.Registration = webauthn.TimeoutConfig{
			Timeout: timeout,
			Enforce: true,
		}
	}

	web, err := webauthn.New(webAuthnConfig)
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(
			herodot.ErrInternalServerError.WithReasonf("Unable to create webauthn config: %s", err)))
		return
	}

	// Determine display name
	displayName := body.DisplayName
	if displayName == "" {
		displayName = extractDisplayName(i.Traits)
	}

	// Generate a user handle (random, as Kratos passkey strategy does)
	userHandle := []byte(randx.MustString(64, randx.AlphaNum))

	user := &adminWebAuthnUser{
		name:   displayName,
		id:     userHandle,
		config: webAuthnConfig,
	}

	// Custom Registration Options
	var registrationOpts []webauthn.RegistrationOption

	// Restrict algorithms to ES256 (-7) and RS256 (-257) explicitly
	registrationOpts = append(registrationOpts, webauthn.WithCredentialParameters([]protocol.CredentialParameter{
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
	}))

	// If the identity already has passkey credentials, exclude them
	if cred, ok := i.GetCredentials(CredentialsTypePasskey); ok {
		var existingConfig CredentialsWebAuthnConfig
		if err := json.Unmarshal(cred.Config, &existingConfig); err == nil {
			user.credentials = existingConfig.Credentials.ToWebAuthn()
		}
	}

	option, sessionData, err := web.BeginRegistration(user, registrationOpts...)
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(
			herodot.ErrInternalServerError.WithReasonf("Unable to begin WebAuthn registration: %s", err)))
		return
	}

	// Store pending registration
	registrationID := uuid.Must(uuid.NewV4())
	pendingRegistrationsLock.Lock()
	pendingRegistrations[registrationID] = &pendingWebAuthnRegistration{
		IdentityID:  identityID,
		SessionData: sessionData,
		UserHandle:  userHandle,
		CreatedAt:   time.Now().UTC(),
	}
	pendingRegistrationsLock.Unlock()

	h.r.Writer().Write(w, r, &AdminWebAuthnRegistrationOptionsResponse{
		RegistrationID:            registrationID,
		CredentialCreationOptions: option,
	})
}

// swagger:route POST /admin/identities/{id}/webauthn/registration-complete identity adminCompleteWebAuthnRegistration
//
// # Complete WebAuthn Registration
//
// Complete a pending WebAuthn registration by providing the credential creation response
// from the authenticator. The credential will be added to the identity's passkey credentials.
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
//	Schemes: http, https
//
//	Security:
//	  oryAccessToken:
//
//	Responses:
//	  200: adminWebAuthnRegistrationCompleteResponse
//	  400: errorGeneric
//	  404: errorGeneric
//	  default: errorGeneric
func (h *Handler) completeWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identityID := x.ParseUUID(r.PathValue("id"))

	var body AdminCompleteWebAuthnRegistrationBody
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&body); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest.WithError(err.Error())))
		return
	}

	if body.RegistrationID == uuid.Nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(
			herodot.ErrBadRequest.WithReason("registration_id is required")))
		return
	}

	// Retrieve and validate pending registration
	pendingRegistrationsLock.Lock()
	pending, ok := pendingRegistrations[body.RegistrationID]
	if ok {
		delete(pendingRegistrations, body.RegistrationID)
	}
	pendingRegistrationsLock.Unlock()

	if !ok {
		h.r.Writer().WriteError(w, r, errors.WithStack(
			herodot.ErrNotFound.WithReason("Registration not found or already completed. Did the registration expire?")))
		return
	}

	if pending.IdentityID != identityID {
		h.r.Writer().WriteError(w, r, errors.WithStack(
			herodot.ErrBadRequest.WithReason("Registration does not belong to this identity")))
		return
	}

	// Parse the credential creation response
	credentialResponse, err := protocol.ParseCredentialCreationResponseBody(
		strings.NewReader(string(body.CredentialCreationResponse)))
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(
			herodot.ErrBadRequest.WithReasonf("Unable to parse credential creation response: %s", err)))
		return
	}

	// Rebuild the webauthn config to validate the credential
	baseConfig := h.r.Config().PasskeyConfig(ctx)
	webAuthnConfig := &webauthn.Config{
		RPDisplayName:         baseConfig.RPDisplayName,
		RPID:                  baseConfig.RPID,
		RPOrigins:             baseConfig.RPOrigins,
		AttestationPreference: protocol.ConveyancePreference("none"),
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: boolPtr(true),
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationRequired,
		},
		EncodeUserIDAsString: false,
	}

	web, err := webauthn.New(webAuthnConfig)
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(
			herodot.ErrInternalServerError.WithReasonf("Unable to create webauthn config: %s", err)))
		return
	}

	credential, err := web.CreateCredential(
		&adminWebAuthnUser{
			id:     pending.UserHandle,
			config: webAuthnConfig,
		},
		*pending.SessionData,
		credentialResponse,
	)
	if err != nil {
		if devErr := new(protocol.Error); errors.As(err, &devErr) {
			h.r.Writer().WriteError(w, r, errors.WithStack(
				herodot.ErrBadRequest.WithReasonf("WebAuthn credential validation failed: %s (dev: %s)", err, devErr.DevInfo)))
		} else {
			h.r.Writer().WriteError(w, r, errors.WithStack(
				herodot.ErrBadRequest.WithReasonf("WebAuthn credential validation failed: %s", err)))
		}
		return
	}

	// Load identity and add credential
	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(ctx, identityID)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	// Build the credential in Kratos format
	credentialWebAuthn := CredentialFromWebAuthn(credential, true)

	// Get existing passkey credentials or create new config
	existingCred := i.GetCredentialsOr(CredentialsTypePasskey, &Credentials{Config: []byte("{}")})
	var cc CredentialsWebAuthnConfig
	if len(existingCred.Config) > 0 && string(existingCred.Config) != "{}" {
		if err := json.Unmarshal(existingCred.Config, &cc); err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(
				herodot.ErrInternalServerError.WithReasonf("Unable to decode existing credentials: %s", err)))
			return
		}
	}

	// Append the new credential
	cc.Credentials = append(cc.Credentials, *credentialWebAuthn)
	if len(cc.UserHandle) == 0 {
		cc.UserHandle = pending.UserHandle
	}

	credentialsConfig, err := json.Marshal(cc)
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(
			herodot.ErrInternalServerError.WithReasonf("Unable to encode credentials: %s", err)))
		return
	}

	// Update the identity with the new credential
	i.UpsertCredentialsConfig(CredentialsTypePasskey, credentialsConfig, 1,
		WithAdditionalIdentifier(string(pending.UserHandle)))

	if err := h.r.IdentityManager().Update(ctx, i, ManagerAllowWriteProtectedTraits); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().Write(w, r, &AdminWebAuthnRegistrationCompleteResponse{
		CredentialID: toHexString(credential.ID),
		Status:       "ok",
	})
}

func boolPtr(b bool) *bool { return &b }

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func extractDisplayName(traits Traits) string {
	var traitMap map[string]interface{}
	if err := json.Unmarshal([]byte(traits), &traitMap); err != nil {
		return ""
	}

	if dn, ok := traitMap["display_name"].(string); ok && dn != "" {
		return dn
	}

	firstName, _ := traitMap["first_name"].(string)
	lastName, _ := traitMap["last_name"].(string)
	if firstName != "" || lastName != "" {
		return strings.TrimSpace(firstName + " " + lastName)
	}

	if email, ok := traitMap["email"].(string); ok && email != "" {
		return email
	}

	return "User"
}

func toHexString(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}
