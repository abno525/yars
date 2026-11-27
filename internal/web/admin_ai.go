package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/rules"
)

// aiAdmin is Admin › AI: the provider, address and model used by AI rules,
// the key (stored encrypted, shown by its ending; the environment variable
// named in config.yaml wins at config.yaml's provider and address), the last
// Test and the AI rules.
type aiAdmin struct {
	Providers                []option
	BaseURL, Model           string
	KeyEnding                string // the stored key's ending ("" = none)
	EnvName                  string // api_key_env from config.yaml
	EnvSet                   bool   // … and set: it is the key in use
	State, StateLabel, Error string
	Test                     *aiTestResult
	Rules                    []option // Value = rule id, Label = level
	PriceIn, PriceOut        string   // per million tokens ("" = no price; D24)
}

type aiTestResult struct {
	OK              bool
	At, Took, Error string
}

// AI settings keys (server_settings).
const (
	aiProviderKey = db.AIProviderKey
	aiBaseKey     = db.AIBaseKey
	aiModelKey    = db.AIModelKey
	aiKeyKey      = db.AIKeyKey // encrypted
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

// wireAI lets the AI rules use the settings saved on the admin page,
// records every call to the provider (Admin › System, AI usage) and keeps
// the results of script and AI rules in the database (Q1, Q16).
func (s *Server) wireAI() {
	rn := s.runner()
	if rn == nil || s.Store == nil || s.Store.DB() == nil {
		return
	}
	if rn.Stored == nil {
		rn.Stored = s.aiStored
	}
	if rn.OnUsage == nil {
		rn.OnUsage = s.recordAI(s.Store.DB())
	}
	if rn.Results == nil {
		rn.Results = s.Store.DB()
	}
}

// aiStored reads the admin page's AI settings and decrypts the key.
func (s *Server) aiStored() (config.AIConfig, string) {
	return s.Store.DB().AIStored(s.secrets)
}

func (s *Server) aiPage(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	s.adminPage(w, r, "ai", status, func(p *page) error {
		stored, key := s.aiStored()
		conf := s.conf().AI
		eff := conf
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
		d := s.Store.DB()
		v.PriceIn, _ = d.Setting(db.AIPriceInKey)
		v.PriceOut, _ = d.Setting(db.AIPriceOutKey)
		if key != "" {
			v.KeyEnding = ending(key)
		}
		// the env key is used only at config.yaml's provider and address
		v.EnvSet = rules.EnvKeyApplies(conf, eff) && os.Getenv(v.EnvName) != ""
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
	priceIn, priceOut := strings.TrimSpace(r.FormValue("price_in")), strings.TrimSpace(r.FormValue("price_out"))
	switch {
	case (priceIn != "" && !aiPrice.MatchString(priceIn)) || (priceOut != "" && !aiPrice.MatchString(priceOut)):
		s.aiPage(w, r, http.StatusBadRequest, "Price: a number with up to 4 decimals, per 1M tokens")
		return
	case prov != "" && prov != rules.ProviderOff && prov != "openai" && prov != "anthropic":
		s.aiPage(w, r, http.StatusBadRequest, "Provider: OpenAI-compatible, Anthropic or Off")
		return
	case !validBaseURL(base):
		s.aiPage(w, r, http.StatusBadRequest, "Address: https (http only for localhost)")
		return
	}
	d := s.Store.DB()
	for k, v := range map[string]string{aiProviderKey: prov, aiBaseKey: base, aiModelKey: model, db.AIPriceInKey: priceIn, db.AIPriceOutKey: priceOut} {
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
	if priceIn != "" || priceOut != "" {
		detail += " price " + priceIn + "/" + priceOut
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
		ctx, cancel := context.WithTimeout(rules.WithCaller(r.Context(), rules.Caller{User: auth.UserFrom(r.Context()).Username}), 25*time.Second)
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
