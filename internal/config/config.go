package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type TelegramChannel struct {
	Name     string `yaml:"name" json:"name"`
	Username string `yaml:"username" json:"username"`
}

type TagSet struct {
	Regions    []string `yaml:"regions,omitempty"    json:"regions"`
	Sectors    []string `yaml:"sectors,omitempty"    json:"sectors"`
	Activities []string `yaml:"activities,omitempty" json:"activities"`
}

type Config struct {
	Feeds            []Feed             `yaml:"feeds"`
	Profile          Profile            `yaml:"profile"`
	Model            string             `yaml:"model"`
	EnrichModel      string             `yaml:"enrich_model"`
	TopN             int                `yaml:"top_n"`
	MinScore         float64            `yaml:"min_score"`
	Listen           string             `yaml:"listen"`
	APIKey           string             `yaml:"api_key"`
	OTXApiKey        string             `yaml:"otx_api_key"`
	CloudflareKey    string             `yaml:"cloudflare_api_key"`
	TelegramAPIID    int                `yaml:"telegram_api_id"`
	TelegramAPIHash  string             `yaml:"telegram_api_hash"`
	TelegramChannels       []TelegramChannel  `yaml:"telegram_channels"`
	TelegramAutoApprove    bool               `yaml:"telegram_auto_approve"`
	TelegramAutoThreshold  int                `yaml:"telegram_auto_threshold"`
	FetchWindow            int                `yaml:"fetch_window"`
	AutoSync         bool               `yaml:"auto_sync"`
	SyncInterval     int                `yaml:"sync_interval"`
	ActorNaming      string             `yaml:"actor_naming"`
	MapAlertMinutes  int                `yaml:"map_alert_minutes"`
	DefaultTags          TagSet             `yaml:"default_tags"`
	LikelihoodWeights   LikelihoodWeights  `yaml:"likelihood_weights"`
}

type Feed struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

type Profile struct {
	Role      string   `yaml:"role"`
	Interests []string `yaml:"interests"`
	Sectors   []string `yaml:"sectors"`
	Regions   []string `yaml:"regions"`
}

type LikelihoodWeights struct {
	Frequency   float64 `yaml:"frequency"`
	Persistence float64 `yaml:"persistence"`
	Recency     float64 `yaml:"recency"`
	Verified    float64 `yaml:"verified"`
	GeoFit      float64 `yaml:"geo_fit"`
	HalfLifeH   float64 `yaml:"half_life_h"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Defaults
	if cfg.Model == "" {
		cfg.Model = "claude-haiku-4-5-20251001"
	}
	if cfg.TopN == 0 {
		cfg.TopN = 20
	}
	if cfg.MinScore == 0 {
		cfg.MinScore = 5.0
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8080"
	}
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if cfg.FetchWindow == 0 {
		cfg.FetchWindow = 7
	}
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 360
	}
	if cfg.ActorNaming == "" {
		cfg.ActorNaming = "mitre"
	}
	if cfg.MapAlertMinutes == 0 {
		cfg.MapAlertMinutes = 60
	}
	if cfg.EnrichModel == "" {
		cfg.EnrichModel = cfg.Model
	}
	if cfg.TelegramAutoThreshold == 0 {
		cfg.TelegramAutoThreshold = 3
	}
	if len(cfg.TelegramChannels) == 0 {
		cfg.TelegramChannels = DefaultTelegramChannels()
	}
	if cfg.LikelihoodWeights.Frequency == 0 {
		cfg.LikelihoodWeights = LikelihoodWeights{
			Frequency: 40, Persistence: 25, Recency: 20,
			Verified: 10, GeoFit: 5, HalfLifeH: 72,
		}
	}

	return cfg, nil
}

func DefaultTelegramChannels() []TelegramChannel {
	return []TelegramChannel{
		{Name: "Server Killers", Username: "ServerKillersRus"},
		{Name: "Dark Storm Team", Username: "Darkstormre"},
		{Name: "Dark Storm Team (back)", Username: "Darkstormteamback"},
		{Name: "Dark Storm Team (new)", Username: "Darkstormteamnewteam"},
		{Name: "Z-Pentest Alliance", Username: "zpentestalliance"},
		{Name: "Z-Pentest", Username: "Z_PEN_TEST"},
		{Name: "РУБЕЖ", Username: "Frontier_channel"},
		{Name: "Keymous+", Username: "KeymousTeam"},
		{Name: "Keymous+ (alt)", Username: "Keymous"},
		{Name: "Coup Team", Username: "CoupTeam"},
		{Name: "DieNet", Username: "DIeNlt"},
		{Name: "NoName057(16) Eng", Username: "nnm05716english"},
		{Name: "CREW RUSSIA", Username: "crewruss1a"},
		{Name: "DCG", Username: "dcg_muslims"},
		{Name: "inteid", Username: "inteid"},
		{Name: "Furqan Alliance", Username: "Al_Furqan_Global"},
		{Name: "Tunisian Maskers", Username: "CyberforceTn"},
		{Name: "AvangardSec", Username: "AvangardSec"},
		{Name: "RubiconH4CK", Username: "rubiconhack"},
		{Name: "THUNDER CYBER", Username: "THUNDER_CYBER_TEAM"},
		{Name: "FloodHacking", Username: "digitalsghost"},
		{Name: "REVOLUSI HIME666", Username: "revolusihime666"},
		{Name: "WE ARE KILLNET", Username: "WeAreKillnet_Channel"},
	}
}

func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
