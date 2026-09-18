// Command review is the operator surface for the review queue.
//
// It talks to PostgreSQL directly rather than exposing HTTP admin endpoints:
// the ingestion API has no authentication, and this tool mutates the source
// registry, so it runs with the database credentials the worker already uses.
//
// Usage:
//
//	review list [--status pending] [--fingerprint F] [--limit N]
//	review show <review_id>
//	review approve <review_id> --contract <file.json> --by <who> [--notes text]
//	review reject  <review_id> --by <who> [--notes text]
//	review reopen  <review_id> --by <who> [--notes text]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
	"github.com/Krishiv-Mahajan/LogMorph/internal/registry"
	"github.com/Krishiv-Mahajan/LogMorph/internal/review"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/postgres"
)

const usage = `review — operator surface for the LogMorph review queue

Commands:
  list     [--status pending|approved|rejected] [--fingerprint F] [--limit N]
  show     <review_id>
  approve  <review_id> --contract <file.json> --by <who> [--notes text]
  reject   <review_id> --by <who> [--notes text]
  reopen   <review_id> --by <who> [--notes text]

Connection settings come from the environment (POSTGRES_DSN, or
POSTGRES_HOST / POSTGRES_PORT / POSTGRES_USER / POSTGRES_PASSWORD /
POSTGRES_DB / POSTGRES_SSLMODE).`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	command := os.Args[1]
	args := os.Args[2:]

	ctx := context.Background()

	db, err := postgres.OpenWithRetry(ctx, postgres.ConfigFromEnv(), 5, time.Second)
	if err != nil {
		fail("cannot reach PostgreSQL: %v", err)
	}
	defer db.Close()

	// The CLI is often the first thing run against a fresh database.
	if err := postgres.Migrate(ctx, db); err != nil {
		fail("cannot apply migrations: %v", err)
	}

	store := review.NewPostgresStore(db)
	mappings := registry.NewPostgresStore(db)

	switch command {
	case "list":
		err = runList(ctx, store, args)
	case "show":
		err = runShow(ctx, store, mappings, args)
	case "approve":
		err = runApprove(ctx, store, mappings, args)
	case "reject":
		err = runReject(ctx, store, args)
	case "reopen":
		err = runReopen(ctx, store, args)
	case "-h", "--help", "help":
		fmt.Println(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", command, usage)
		os.Exit(2)
	}

	if err != nil {
		fail("%v", err)
	}
}

func runList(ctx context.Context, store review.Store, args []string) error {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	status := flags.String("status", "", "filter by status: pending, approved or rejected")
	fingerprint := flags.String("fingerprint", "", "filter by source fingerprint")
	limit := flags.Int("limit", 50, "maximum items to return")
	if err := flags.Parse(args); err != nil {
		return err
	}

	items, err := store.List(ctx, review.Filter{
		Status:      review.Status(*status),
		Fingerprint: *fingerprint,
		Limit:       *limit,
	})
	if err != nil {
		return err
	}

	if len(items) == 0 {
		fmt.Println("no review items match")
		return nil
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "ID\tSTATUS\tCATEGORY\tDRIFT\tMAPPING\tOCCURRENCES\tLAST SEEN\tSOURCE")
	for _, item := range items {
		fmt.Fprintf(writer, "%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			item.ReviewID,
			item.Status,
			item.Category,
			item.DriftStatus,
			formatMapping(item.MappingID, item.MappingVersion),
			item.Occurrences,
			item.LastSeenAt.Format(time.RFC3339),
			shortFingerprint(item.Fingerprint),
		)
	}

	return writer.Flush()
}

func runShow(ctx context.Context, store review.Store, mappings registry.Store, args []string) error {
	reviewID, err := parseReviewID(args)
	if err != nil {
		return err
	}

	item, err := store.Get(ctx, reviewID)
	if err != nil {
		return err
	}

	fmt.Printf("review_id           %d\n", item.ReviewID)
	fmt.Printf("status              %s\n", item.Status)
	fmt.Printf("category            %s\n", item.Category)
	fmt.Printf("fingerprint         %s\n", item.Fingerprint)
	fmt.Printf("signature           %s\n", item.Signature)
	fmt.Printf("mapping             %s\n", formatMapping(item.MappingID, item.MappingVersion))
	fmt.Printf("drift_status        %s\n", item.DriftStatus)
	fmt.Printf("reason              %s\n", item.Reason)
	fmt.Printf("origin              %s\n", item.Origin)
	fmt.Printf("sample_event_id     %s\n", valueOr(item.SampleEventID, "(none)"))
	fmt.Printf("occurrences         %d\n", item.Occurrences)
	fmt.Printf("first_seen_at       %s\n", item.FirstSeenAt.Format(time.RFC3339))
	fmt.Printf("last_seen_at        %s\n", item.LastSeenAt.Format(time.RFC3339))
	if item.DecidedAt != nil {
		fmt.Printf("decided_at          %s\n", item.DecidedAt.Format(time.RFC3339))
		fmt.Printf("decided_by          %s\n", valueOr(item.DecidedBy, "(unknown)"))
		fmt.Printf("decision_notes      %s\n", valueOr(item.DecisionNotes, "(none)"))
	}
	if item.ResultingMappingVersion > 0 {
		fmt.Printf("resulting_mapping   v%d\n", item.ResultingMappingVersion)
	}

	fmt.Println("\nobserved changes:")
	for _, change := range item.Changes {
		fmt.Printf("  %-26s field=%-24s target=%s\n", change.Kind, change.Field, valueOr(change.Target, "-"))
	}
	if len(item.Changes) == 0 {
		fmt.Println("  (none recorded)")
	}

	// The active mapping the source is using right now, for comparison with a
	// proposal. A source with no contract has no active mapping.
	if active, err := mappings.ActiveFor(ctx, item.Fingerprint); err == nil {
		fmt.Printf("\nactive mapping: %s v%d (%d fields)\n",
			active.MappingID, active.MappingVersion, len(active.Contract.Fields))
		for _, field := range active.Contract.Fields {
			fmt.Printf("  %-24s %-8s target=%s%s\n",
				field.Name, field.Type, valueOr(field.Target, "-"), requiredMark(field.Optional))
		}
	} else {
		fmt.Println("\nactive mapping: none (this source has no contract)")
	}

	if item.ProposedContract != nil {
		fmt.Printf("\nproposed contract (%d fields):\n", len(item.ProposedContract.Fields))
		for _, field := range item.ProposedContract.Fields {
			fmt.Printf("  %-24s %-8s target=%s%s\n",
				field.Name, field.Type, valueOr(field.Target, "-"), requiredMark(field.Optional))
		}
	}

	return nil
}

func runApprove(ctx context.Context, store review.Store, mappings registry.Store, args []string) error {
	flags := flag.NewFlagSet("approve", flag.ContinueOnError)
	contractPath := flags.String("contract", "", "path to the proposed contract (JSON)")
	by := flags.String("by", "", "who is approving")
	notes := flags.String("notes", "", "decision notes")
	positional, err := splitFlags(args, flags)
	if err != nil {
		return err
	}

	reviewID, err := parseReviewID(positional)
	if err != nil {
		return err
	}
	if *contractPath == "" {
		return fmt.Errorf("--contract is required: approval must state the mapping to activate")
	}
	if *by == "" {
		return fmt.Errorf("--by is required")
	}

	proposed, err := loadContract(*contractPath)
	if err != nil {
		return err
	}

	item, err := review.Approve(ctx, store, mappings, reviewID, proposed, *by, *notes)
	if err != nil {
		return err
	}

	fmt.Printf("review %d approved by %s\n", item.ReviewID, item.DecidedBy)
	fmt.Printf("activated mapping version v%d for source %s\n",
		item.ResultingMappingVersion, shortFingerprint(item.Fingerprint))
	fmt.Println("the previous version remains in the registry as superseded")

	return nil
}

func runReject(ctx context.Context, store review.Store, args []string) error {
	flags := flag.NewFlagSet("reject", flag.ContinueOnError)
	by := flags.String("by", "", "who is rejecting")
	notes := flags.String("notes", "", "decision notes")
	positional, err := splitFlags(args, flags)
	if err != nil {
		return err
	}

	reviewID, err := parseReviewID(positional)
	if err != nil {
		return err
	}
	if *by == "" {
		return fmt.Errorf("--by is required")
	}

	item, err := review.Reject(ctx, store, reviewID, *by, *notes)
	if err != nil {
		return err
	}

	fmt.Printf("review %d rejected by %s\n", item.ReviewID, item.DecidedBy)
	fmt.Println("the source keeps its current mapping; the registry was not changed")

	return nil
}

func runReopen(ctx context.Context, store review.Store, args []string) error {
	flags := flag.NewFlagSet("reopen", flag.ContinueOnError)
	by := flags.String("by", "", "who is reopening")
	notes := flags.String("notes", "", "reason for reopening")
	positional, err := splitFlags(args, flags)
	if err != nil {
		return err
	}

	reviewID, err := parseReviewID(positional)
	if err != nil {
		return err
	}
	if *by == "" {
		return fmt.Errorf("--by is required")
	}

	item, err := store.Reopen(ctx, reviewID, *by, *notes)
	if err != nil {
		return err
	}

	fmt.Printf("review %d reopened by %s and is pending again\n", item.ReviewID, item.DecidedBy)

	return nil
}

// splitFlags allows the review id and the flags to be given in either order.
func splitFlags(args []string, flags *flag.FlagSet) ([]string, error) {
	positional := make([]string, 0, 1)
	flagArgs := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			// A flag written as "--name value" takes the next argument too.
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, arg)
	}

	if err := flags.Parse(flagArgs); err != nil {
		return nil, err
	}

	return positional, nil
}

func parseReviewID(args []string) (int64, error) {
	if len(args) != 1 {
		return 0, fmt.Errorf("expected exactly one review id")
	}

	reviewID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid review id %q", args[0])
	}

	return reviewID, nil
}

// loadContract reads a proposed contract from a JSON file.
func loadContract(path string) (contract.Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contract.Contract{}, fmt.Errorf("cannot read contract file: %w", err)
	}

	var proposed contract.Contract
	if err := json.Unmarshal(data, &proposed); err != nil {
		return contract.Contract{}, fmt.Errorf("contract file is not a valid contract: %w", err)
	}

	return proposed, nil
}

func formatMapping(mappingID string, version int) string {
	if mappingID == "" || version == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%s v%d", mappingID, version)
}

func shortFingerprint(fingerprint string) string {
	if len(fingerprint) <= 12 {
		return fingerprint
	}
	return fingerprint[:12]
}

func requiredMark(optional bool) string {
	if optional {
		return " (optional)"
	}
	return " (required)"
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "review: "+format+"\n", args...)
	os.Exit(1)
}
