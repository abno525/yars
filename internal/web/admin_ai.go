package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/rules"
)

// aiAdmin is Admin › AI: the provider, address and model used by AI rules,
// the key (stored encrypted, shown by its ending; the environment variable
// named in config.yaml still wins), the last Test and the AI rules.
type aiAdmin struct {
	Providers                []option
	BaseURL, Model           string
	KeyEnding                string // the stored key's ending ("" = none)
	EnvName                  string // api_key_env from config.yaml
	EnvSet                   bool   // … and set: it is the key in use
	State, StateLabel, Error string
	Test                     *aiTestResult
	Rules                    []option // Value = rule id, Label = level
}

type aiTestResult struct {
	OK              bool
	At, Took, Error string
}

// AI settings keys (server_settings).
const (
	aiProviderKey = "ai.provider"
	aiBaseKey     = "ai.base_url"
	aiModelKey    = "ai.model"
	aiKeyKey      = "ai.key" // encrypted
)

var aiProviders = []option{{Value: "openai", Label: "OpenAI-compatible"}, {Value: "anthropic", Label: "Anthropic"}, {Value: rules.ProviderOff, Label: "Off"}}

func (s *Server) routesAdminAI(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/ai", s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		s.aiPage(w, r, http.StatusOK, "")
	}))
	mux.HandleFunc("POST /admin/ai", s.adminOnly(s.aiSave))
	mux.HandleFunc("POST /admin/ai/test", s.adminOnly(s.aiTestRun))
}

// runner is the rules engine's runner for script and AI rules (nil when
// there is none).
func (s *Server) runner() *rules.Runner {
	if s.Rules == nil {
		return nil
	}
	rn, _ := s.Rules.Runner.(*rules.Runner)
	return rn
}

// wireAI lets the AI rules use the settings saved on the admin page.
func (s *Server) wireAI() {
	if rn := s.runner(); rn != nil && rn.Stored == nil && s.Store != nil && s.Store.DB() != nil {
		rn.Stored = s.aiStored
	}
}

// aiStored reads the admin page's AI settings and decrypts the key.
func (s *Server) aiStored() (config.AIConfig, string) {
	all, err := s.Store.DB().Settings("ai.")
	if err != nil {
		return config.AIConfig{}, ""
	}
	c := config.AIConfig{Provider: all[aiProviderKey], BaseURL: all[aiBaseKey], Model: all[aiModelKey]}
	key := ""
	if enc := all[aiKeyKey]; enc != "" {
		if box, err := s.secrets(); err == nil {
			key, _ = box.Decrypt(enc)
		}
	}
	return c, key
}

func (s *Server) aiPage(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	s.adminPage(w, r, "ai", status, func(p *page) error {
		stored, key := s.aiStored()
		eff := s.conf().AI
		if stored.Provider != "" {
			eff.Provider = stored.Provider
		}
		if stored.BaseURL != "" {
			eff.BaseURL = stored.BaseURL
		}
		if stored.Model != "" {
			eff.Model = stored.Model
		}
		v := aiAdmin{BaseURL: eff.BaseURL, Model: eff.Model, EnvName: eff.APIKeyEnv, Error: errMsg, Test: s.aiTest.Load()}
		if key != "" {
			v.KeyEnding = ending(key)
		}
		v.EnvSet = v.EnvName != "" && os.Getenv(v.EnvName) != ""
		prov := eff.Provider
		if prov == "" {
			prov = rules.ProviderOff
		}
		for _, o := range aiProviders {
			o.On = o.Value == prov
			v.Providers = append(v.Providers, o)
		}
		switch {
		case prov == rules.ProviderOff:
			v.State, v.StateLabel = "off", "Off"
		case key == "" && !v.EnvSet:
			v.State, v.StateLabel = "bad", "No key"
		case v.Test != nil && !v.Test.OK:
			v.State, v.StateLabel = "bad", "Failed"
		case v.Test != nil:
			v.State, v.StateLabel = "good", "Connected"
		default:
			v.State, v.StateLabel = "idle", "Not tested"
		}
		if s.Rules != nil {
			for _, rl := range s.Rules.Rules().Rules {
				if rl.AI != "" {
					v.Rules = append(v.Rules, option{Value: rl.ID, Label: rl.Level})
				}
			}
		}
		p.Admin.AI = v
		return nil
	})
}

// validBaseURL: https, or plain http only for this machine (as config.yaml).
func validBaseURL(b string) bool {
	if b == "" {
		return true
	}
	u, err := url.Parse(b)
	if err != nil || u.Host == "" {
		return false
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	return u.Scheme == "https" || (u.Scheme == "http" && local)
}

// aiSave stores the AI settings; an empty key field keeps the stored key.
func (s *Server) aiSave(w http.ResponseWriter, r *http.Request) {
	prov := r.FormValue("provider")
	base := strings.TrimSpace(r.FormValue("base_url"))
	model := strings.TrimSpace(r.FormValue("model"))
	key := strings.TrimSpace(r.FormValue("key"))
	switch {
	case prov != "" && prov != rules.ProviderOff && prov != "openai" && prov != "anthropic":
		s.aiPage(w, r, http.StatusBadRequest, "Provider: OpenAI-compatible, Anthropic or Off")
		return
	case !validBaseURL(base):
		s.aiPage(w, r, http.StatusBadRequest, "Address: https (http only for localhost)")
		return
	}
	d := s.Store.DB()
	for k, v := range map[string]string{aiProviderKey: prov, aiBaseKey: base, aiModelKey: model} {
		if err := d.SetSetting(k, v); err != nil {
			s.fail(w, err)
			return
		}
	}
	if key != "" {
		box, err := s.secrets()
		if err != nil {
			s.fail(w, err)
			return
		}
		enc, err := box.Encrypt(key)
		if err != nil {
			s.fail(w, err)
			return
		}
		if err := d.SetSetting(aiKeyKey, enc); err != nil {
			s.fail(w, err)
			return
		}
	}
	s.aiTest.Store(nil) // a new setting is untested
	detail := prov + " " + model
	if key != "" {
		detail += " key " + ending(key)
	}
	d.Audit(auth.UserFrom(r.Context()).Username, "settings.ai", "", strings.TrimSpace(detail))
	http.Redirect(w, r, "/admin/ai", http.StatusSeeOther)
}

// aiTestRun asks the provider in use for a minimal reply and shows how it
// went.
func (s *Server) aiTestRun(w http.ResponseWriter, r *http.Request) {
	res := &aiTestResult{At: time.Now().Format("15:04")}
	if rn := s.runner(); rn == nil {
		res.Error = "no rules engine"
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		took, err := rn.Ping(ctx)
		cancel()
		if err != nil {
			res.Error = err.Error()
		} else {
			res.OK, res.Took = true, dur(took)
		}
	}
	s.aiTest.Store(res)
	s.aiPage(w, r, http.StatusOK, "")
}
