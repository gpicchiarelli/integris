// Command integris-assure validates Integris assurance records and renders the
// human-readable traceability matrix. It is assurance tooling, not product code.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const tracePath = "docs/traceability.md"

var (
	requirementID  = regexp.MustCompile(`^INT-IC[1-4]-[0-9]{4}$`)
	hazardID       = regexp.MustCompile(`^HAZ-[0-9]{4}$`)
	threatID       = regexp.MustCompile(`^THR-[0-9]{4}$`)
	verificationID = regexp.MustCompile(
		`^VER-[A-Z][A-Z0-9-]*-[0-9]{3}$`,
	)
	evidenceID = regexp.MustCompile(`^EVD-[A-Z][A-Z0-9-]*-[0-9]{3}$`)
)

type requirementFile struct {
	SchemaVersion int           `json:"schema_version"`
	Baseline      string        `json:"baseline"`
	Requirements  []Requirement `json:"requirements"`
}

type Requirement struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Statement         string   `json:"statement"`
	Criticality       string   `json:"criticality"`
	Status            string   `json:"status"`
	Rationale         string   `json:"rationale"`
	InitialConditions []string `json:"initial_conditions"`
	FinalConditions   []string `json:"final_conditions"`
	Hazards           []string `json:"hazards"`
	Threats           []string `json:"threats"`
	Specifications    []string `json:"specifications"`
	Verifications     []string `json:"verifications"`
	Owner             string   `json:"owner"`
	ApproverRoles     []string `json:"approver_roles"`
}

type hazardFile struct {
	SchemaVersion int      `json:"schema_version"`
	Analysis      string   `json:"analysis"`
	Hazards       []Hazard `json:"hazards"`
}

type Hazard struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Severity     string   `json:"severity"`
	Causes       []string `json:"causes"`
	Consequence  string   `json:"consequence"`
	Controls     []string `json:"controls"`
	ResidualRisk string   `json:"residual_risk"`
	Owner        string   `json:"owner"`
}

type threatFile struct {
	SchemaVersion int      `json:"schema_version"`
	Method        string   `json:"method"`
	Threats       []Threat `json:"threats"`
}

type Threat struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Stride        []string `json:"stride"`
	Assets        []string `json:"assets"`
	TrustBoundary string   `json:"trust_boundary"`
	Attack        string   `json:"attack"`
	Controls      []string `json:"controls"`
	ResidualRisk  string   `json:"residual_risk"`
	Owner         string   `json:"owner"`
}

type verificationFile struct {
	SchemaVersion int            `json:"schema_version"`
	Verifications []Verification `json:"verifications"`
}

type Verification struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Level        string   `json:"level"`
	Methods      []string `json:"methods"`
	Requirements []string `json:"requirements"`
	Criterion    string   `json:"criterion"`
	Evidence     []string `json:"evidence"`
	Status       string   `json:"status"`
	Owner        string   `json:"owner"`
}

type evidenceFile struct {
	SchemaVersion int        `json:"schema_version"`
	Evidence      []Evidence `json:"evidence"`
}

type Evidence struct {
	ID           string `json:"id"`
	Verification string `json:"verification"`
	Status       string `json:"status"`
	Location     string `json:"location"`
	Producer     string `json:"producer"`
	ReviewerRole string `json:"reviewer_role"`
}

type Records struct {
	Baseline      string
	Requirements  []Requirement
	Hazards       []Hazard
	Threats       []Threat
	Verifications []Verification
	Evidence      []Evidence
}

func main() {
	if len(os.Args) < 2 {
		usage("missing command")
	}

	switch os.Args[1] {
	case "validate":
		fs := flag.NewFlagSet("validate", flag.ExitOnError)
		root := fs.String("root", ".", "repository root")
		mustParse(fs, os.Args[2:])
		records, err := load(*root)
		if err == nil {
			err = records.Validate(*root, true)
		}
		if err != nil {
			fatal(err)
		}
		fmt.Printf("assurance records valid: %d requirements, %d hazards, %d threats, %d verifications, %d evidence records\n",
			len(records.Requirements), len(records.Hazards), len(records.Threats), len(records.Verifications), len(records.Evidence))
	case "trace":
		fs := flag.NewFlagSet("trace", flag.ExitOnError)
		root := fs.String("root", ".", "repository root")
		check := fs.Bool("check", false, "fail if the generated file is stale")
		write := fs.Bool("write", false, "write the generated file")
		mustParse(fs, os.Args[2:])
		if *check == *write {
			usage("trace requires exactly one of --check or --write")
		}
		records, err := load(*root)
		if err == nil {
			err = records.Validate(*root, false)
		}
		if err != nil {
			fatal(err)
		}
		want := records.Traceability()
		path := filepath.Join(*root, tracePath)
		if *write {
			if err := os.WriteFile(path, want, 0o644); err != nil {
				fatal(fmt.Errorf("write %s: %w", tracePath, err))
			}
			fmt.Printf("wrote %s\n", tracePath)
			return
		}
		got, err := os.ReadFile(path)
		if err != nil {
			fatal(fmt.Errorf("read generated %s: %w", tracePath, err))
		}
		if !bytes.Equal(got, want) {
			fatal(fmt.Errorf("%s is stale; run: go run ./cmd/integris-assure trace --root . --write", tracePath))
		}
		fmt.Printf("%s is current\n", tracePath)
	default:
		usage("unknown command " + os.Args[1])
	}
}

func mustParse(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if fs.NArg() != 0 {
		usage("unexpected positional arguments")
	}
}

func usage(message string) {
	fmt.Fprintf(os.Stderr, "integris-assure: %s\nusage:\n  integris-assure validate --root DIR\n  integris-assure trace --root DIR (--check | --write)\n", message)
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "integris-assure:", err)
	os.Exit(1)
}

func load(root string) (Records, error) {
	var rf requirementFile
	var hf hazardFile
	var tf threatFile
	var vf verificationFile
	var ef evidenceFile
	for _, item := range []struct {
		path string
		dst  any
	}{
		{"assurance/requirements.json", &rf},
		{"assurance/hazards.json", &hf},
		{"assurance/threats.json", &tf},
		{"assurance/verifications.json", &vf},
		{"assurance/evidence.json", &ef},
	} {
		if err := readStrict(filepath.Join(root, item.path), item.dst); err != nil {
			return Records{}, fmt.Errorf("%s: %w", item.path, err)
		}
	}
	if rf.SchemaVersion != 1 || hf.SchemaVersion != 1 || tf.SchemaVersion != 1 || vf.SchemaVersion != 1 || ef.SchemaVersion != 1 {
		return Records{}, errors.New("all assurance files must use schema_version 1")
	}
	return Records{rf.Baseline, rf.Requirements, hf.Hazards, tf.Threats, vf.Verifications, ef.Evidence}, nil
}

func readStrict(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := ensureEOF(dec); err != nil {
		return err
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(dec); err != nil {
		return err
	}
	return ensureEOF(dec)
}

func scanJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := scanJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func (r Records) Validate(root string, checkProducedEvidence bool) error {
	var problems []string
	reqs := index("requirement", requirementID, ids(r.Requirements, func(v Requirement) string { return v.ID }), &problems)
	hazards := index("hazard", hazardID, ids(r.Hazards, func(v Hazard) string { return v.ID }), &problems)
	threats := index("threat", threatID, ids(r.Threats, func(v Threat) string { return v.ID }), &problems)
	verifications := index("verification", verificationID, ids(r.Verifications, func(v Verification) string { return v.ID }), &problems)
	evidence := index("evidence", evidenceID, ids(r.Evidence, func(v Evidence) string { return v.ID }), &problems)

	if strings.TrimSpace(r.Baseline) == "" {
		problems = append(problems, "baseline is empty")
	}
	for _, q := range r.Requirements {
		requiredText(q.ID, map[string]string{"title": q.Title, "statement": q.Statement, "status": q.Status, "rationale": q.Rationale, "owner": q.Owner}, &problems)
		if q.Criticality != "IC-1" && q.Criticality != "IC-2" && q.Criticality != "IC-3" && q.Criticality != "IC-4" {
			problems = append(problems, q.ID+": invalid criticality "+q.Criticality)
		}
		requireNonEmpty(q.ID, "initial_conditions", q.InitialConditions, &problems)
		requireNonEmpty(q.ID, "final_conditions", q.FinalConditions, &problems)
		requireNonEmpty(q.ID, "hazards", q.Hazards, &problems)
		requireNonEmpty(q.ID, "threats", q.Threats, &problems)
		requireNonEmpty(q.ID, "specifications", q.Specifications, &problems)
		requireNonEmpty(q.ID, "verifications", q.Verifications, &problems)
		requireNonEmpty(q.ID, "approver_roles", q.ApproverRoles, &problems)
		checkRefs(q.ID, "hazard", q.Hazards, hazards, &problems)
		checkRefs(q.ID, "threat", q.Threats, threats, &problems)
		checkRefs(q.ID, "verification", q.Verifications, verifications, &problems)
		for _, id := range q.Hazards {
			if h, ok := findHazard(r.Hazards, id); ok && !contains(h.Controls, q.ID) {
				problems = append(problems, q.ID+" -> "+id+" is not bidirectional")
			}
		}
		for _, id := range q.Threats {
			if t, ok := findThreat(r.Threats, id); ok && !contains(t.Controls, q.ID) {
				problems = append(problems, q.ID+" -> "+id+" is not bidirectional")
			}
		}
		for _, id := range q.Verifications {
			if v, ok := findVerification(r.Verifications, id); ok && !contains(v.Requirements, q.ID) {
				problems = append(problems, q.ID+" -> "+id+" is not bidirectional")
			}
		}
		for _, spec := range q.Specifications {
			checkRepositoryFile(root, q.ID, spec, &problems)
		}
	}
	for _, h := range r.Hazards {
		requiredText(h.ID, map[string]string{"title": h.Title, "severity": h.Severity, "consequence": h.Consequence, "residual_risk": h.ResidualRisk, "owner": h.Owner}, &problems)
		requireNonEmpty(h.ID, "causes", h.Causes, &problems)
		requireNonEmpty(h.ID, "controls", h.Controls, &problems)
		checkRefs(h.ID, "control requirement", h.Controls, reqs, &problems)
		for _, id := range h.Controls {
			if q, ok := findRequirement(r.Requirements, id); ok && !contains(q.Hazards, h.ID) {
				problems = append(problems, h.ID+" -> "+id+" is not bidirectional")
			}
		}
	}
	for _, t := range r.Threats {
		requiredText(t.ID, map[string]string{"title": t.Title, "trust_boundary": t.TrustBoundary, "attack": t.Attack, "residual_risk": t.ResidualRisk, "owner": t.Owner}, &problems)
		requireNonEmpty(t.ID, "stride", t.Stride, &problems)
		requireNonEmpty(t.ID, "assets", t.Assets, &problems)
		requireNonEmpty(t.ID, "controls", t.Controls, &problems)
		checkRefs(t.ID, "control requirement", t.Controls, reqs, &problems)
		for _, id := range t.Controls {
			if q, ok := findRequirement(r.Requirements, id); ok && !contains(q.Threats, t.ID) {
				problems = append(problems, t.ID+" -> "+id+" is not bidirectional")
			}
		}
	}
	for _, v := range r.Verifications {
		requiredText(v.ID, map[string]string{"title": v.Title, "level": v.Level, "criterion": v.Criterion, "status": v.Status, "owner": v.Owner}, &problems)
		requireNonEmpty(v.ID, "methods", v.Methods, &problems)
		requireNonEmpty(v.ID, "evidence", v.Evidence, &problems)
		checkRefs(v.ID, "requirement", v.Requirements, reqs, &problems)
		checkRefs(v.ID, "evidence", v.Evidence, evidence, &problems)
		for _, id := range v.Requirements {
			if q, ok := findRequirement(r.Requirements, id); ok && !contains(q.Verifications, v.ID) {
				problems = append(problems, v.ID+" -> "+id+" is not bidirectional")
			}
		}
	}
	for _, e := range r.Evidence {
		requiredText(e.ID, map[string]string{"verification": e.Verification, "status": e.Status, "location": e.Location, "producer": e.Producer, "reviewer_role": e.ReviewerRole}, &problems)
		checkRefs(e.ID, "verification", []string{e.Verification}, verifications, &problems)
		if v, ok := findVerification(r.Verifications, e.Verification); ok && !contains(v.Evidence, e.ID) {
			problems = append(problems, e.ID+" -> "+e.Verification+" is not bidirectional")
		}
		if e.Status != "planned" && e.Status != "produced" && e.Status != "superseded" {
			problems = append(problems, e.ID+": invalid evidence status "+e.Status)
		}
		if checkProducedEvidence && e.Status == "produced" {
			checkRepositoryFile(root, e.ID, e.Location, &problems)
		}
	}
	if len(problems) != 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func ids[T any](values []T, fn func(T) string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, fn(value))
	}
	return result
}

func index(kind string, pattern *regexp.Regexp, values []string, problems *[]string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, id := range values {
		if !pattern.MatchString(id) {
			*problems = append(*problems, fmt.Sprintf("%s has malformed id %q", kind, id))
		}
		if _, exists := result[id]; exists {
			*problems = append(*problems, fmt.Sprintf("duplicate %s id %q", kind, id))
		}
		result[id] = struct{}{}
	}
	return result
}

func requiredText(id string, fields map[string]string, problems *[]string) {
	for name, value := range fields {
		if strings.TrimSpace(value) == "" {
			*problems = append(*problems, id+": "+name+" is empty")
		}
	}
}

func requireNonEmpty(id, name string, values []string, problems *[]string) {
	if len(values) == 0 {
		*problems = append(*problems, id+": "+name+" is empty")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			*problems = append(*problems, id+": "+name+" contains an empty value")
		}
		if _, exists := seen[value]; exists {
			*problems = append(*problems, id+": "+name+" contains duplicate "+value)
		}
		seen[value] = struct{}{}
	}
}

func checkRefs(owner, kind string, refs []string, known map[string]struct{}, problems *[]string) {
	for _, ref := range refs {
		if _, ok := known[ref]; !ok {
			*problems = append(*problems, owner+": unknown "+kind+" "+ref)
		}
	}
}

func checkRepositoryFile(root, owner, path string, problems *[]string) {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || path == "." || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
		*problems = append(*problems, owner+": invalid repository path "+path)
		return
	}
	current := root
	for _, component := range strings.Split(path, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			*problems = append(*problems, owner+": missing artifact "+path)
			return
		}
		if info.Mode()&os.ModeSymlink != 0 {
			*problems = append(*problems, owner+": artifact path contains a symbolic link "+path)
			return
		}
	}
	info, err := os.Stat(current)
	if err != nil {
		*problems = append(*problems, owner+": missing artifact "+path)
		return
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		*problems = append(*problems, owner+": artifact is not a non-empty regular file "+path)
	}
}

func findRequirement(values []Requirement, id string) (Requirement, bool) {
	for _, value := range values {
		if value.ID == id {
			return value, true
		}
	}
	return Requirement{}, false
}

func findVerification(values []Verification, id string) (Verification, bool) {
	for _, value := range values {
		if value.ID == id {
			return value, true
		}
	}
	return Verification{}, false
}

func findHazard(values []Hazard, id string) (Hazard, bool) {
	for _, value := range values {
		if value.ID == id {
			return value, true
		}
	}
	return Hazard{}, false
}

func findThreat(values []Threat, id string) (Threat, bool) {
	for _, value := range values {
		if value.ID == id {
			return value, true
		}
	}
	return Threat{}, false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (r Records) Traceability() []byte {
	requirements := append([]Requirement(nil), r.Requirements...)
	sort.Slice(requirements, func(i, j int) bool { return requirements[i].ID < requirements[j].ID })
	evidenceByVerification := make(map[string][]Evidence)
	for _, item := range r.Evidence {
		evidenceByVerification[item.Verification] = append(evidenceByVerification[item.Verification], item)
	}
	var b strings.Builder
	b.WriteString("# Traceability matrix\n\n")
	b.WriteString("<!-- Generated by integris-assure. Do not edit by hand. -->\n\n")
	fmt.Fprintf(&b, "Baseline: **%s**\n\nRequirements: **%d** · Hazards: **%d** · Threats: **%d**\n\n", escape(r.Baseline), len(r.Requirements), len(r.Hazards), len(r.Threats))
	b.WriteString("A `planned` evidence record is a declared gap, not proof. Run `make verify` to validate references and freshness.\n\n")
	b.WriteString("| Requirement | Class | Hazards | Threats | Specifications | Verification and evidence | Owner / approval |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, q := range requirements {
		verificationCells := make([]string, 0, len(q.Verifications))
		for _, verificationID := range sorted(q.Verifications) {
			v, _ := findVerification(r.Verifications, verificationID)
			parts := make([]string, 0, len(evidenceByVerification[verificationID]))
			for _, item := range evidenceByVerification[verificationID] {
				parts = append(parts, item.ID+" ("+item.Status+")")
			}
			sort.Strings(parts)
			verificationCells = append(verificationCells, verificationID+" — "+v.Status+"; "+strings.Join(parts, ", "))
		}
		links := make([]string, 0, len(q.Specifications))
		for _, spec := range sorted(q.Specifications) {
			links = append(links, "["+spec+"](../"+spec+")")
		}
		fmt.Fprintf(&b, "| **%s** — %s | %s | %s | %s | %s | %s | %s / %s |\n",
			escape(q.ID), escape(q.Title), escape(q.Criticality), join(q.Hazards), join(q.Threats), strings.Join(links, "<br>"), join(verificationCells), escape(q.Owner), join(q.ApproverRoles))
	}
	b.WriteString("\n## Requirement statements\n\n")
	for _, q := range requirements {
		fmt.Fprintf(&b, "### %s — %s\n\n%s\n\n**Rationale:** %s\n\n**Initial:** %s\n\n**Final:** %s\n\n",
			q.ID, q.Title, q.Statement, q.Rationale, join(q.InitialConditions), join(q.FinalConditions))
	}
	return []byte(strings.TrimRight(b.String(), "\n") + "\n")
}

func sorted(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func join(values []string) string {
	result := sorted(values)
	for i := range result {
		result[i] = escape(result[i])
	}
	return strings.Join(result, "<br>")
}

func escape(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
