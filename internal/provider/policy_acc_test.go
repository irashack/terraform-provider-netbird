//go:build e2e

package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func Test_Policy_Create_Groups(t *testing.T) {
	testE2E(t)
	rName := "po" + acctest.RandStringFromCharSet(10, acctest.CharSetAlpha)
	rNameFull := "netbird_policy." + rName
	var createdID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().Policies.Get, &createdID),
		Steps: []resource.TestStep{
			{
				ResourceName: rName,
				Config:       testPolicyResourceGroups(rName, rName, "desc", "accept", "udp", e2eGroupAllID(), e2eGroupNotAllID(), "443"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "name", rName),
					resource.TestCheckResourceAttr(rNameFull, "description", "desc"),
					resource.TestCheckResourceAttr(rNameFull, "rule.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.action", "accept"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.ports.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.ports.0", "443"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.sources.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.sources.0", e2eGroupAllID()),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.destinations.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.destinations.0", e2eGroupNotAllID()),
					func(s *terraform.State) error {
						pID := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						policy, err := testClient().Policies.Get(context.Background(), pID)
						if err != nil {
							return err
						}

						return matchPairs(map[string][]any{
							"Name":                    {rName, policy.Name},
							"Description":             {"desc", policy.Description},
							"Rules.#":                 {int(1), len(policy.Rules)},
							"Rules[0].Action":         {"accept", string(policy.Rules[0].Action)},
							"Rules[0].Ports.#":        {int(1), len(*policy.Rules[0].Ports)},
							"Rules[0].Ports.0":        {"443", (*policy.Rules[0].Ports)[0]},
							"Rules[0].Sources.#":      {int(1), len(*policy.Rules[0].Sources)},
							"Rules[0].Sources.0":      {e2eGroupAllID(), (*policy.Rules[0].Sources)[0].Id},
							"Rules[0].Destinations.#": {int(1), len(*policy.Rules[0].Destinations)},
							"Rules[0].Destinations.0": {e2eGroupNotAllID(), (*policy.Rules[0].Destinations)[0].Id},
						})
					},
				),
			},
			{
				ResourceName:      rNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func Test_Policy_Create_Resources(t *testing.T) {
	testE2E(t)
	rName := "po" + acctest.RandStringFromCharSet(10, acctest.CharSetAlpha)
	rNameFull := "netbird_policy." + rName
	var createdID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().Policies.Get, &createdID),
		Steps: []resource.TestStep{
			{
				ResourceName: rName,
				Config:       testPolicyResourceResources(rName, rName, "desc", "accept", "udp", e2eResourceSubnetID(), "subnet", e2eResourceDomainID(), "domain", "1000", "2000"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "name", rName),
					resource.TestCheckResourceAttr(rNameFull, "description", "desc"),
					resource.TestCheckResourceAttr(rNameFull, "rule.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.action", "accept"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.ports.#", "0"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.sources.#", "0"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.source_resource.id", e2eResourceSubnetID()),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.source_resource.type", "subnet"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.destination_resource.id", e2eResourceDomainID()),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.destination_resource.type", "domain"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.destinations.#", "0"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.port_ranges.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.port_ranges.0.start", "1000"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.port_ranges.0.end", "2000"),
					func(s *terraform.State) error {
						pID := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						policy, err := testClient().Policies.Get(context.Background(), pID)
						if err != nil {
							return err
						}

						return matchPairs(map[string][]any{
							"Name":                            {rName, policy.Name},
							"Description":                     {"desc", policy.Description},
							"Rules.#":                         {int(1), len(policy.Rules)},
							"Rules[0].Action":                 {"accept", string(policy.Rules[0].Action)},
							"Rules[0].Sources.#":              {nil, policy.Rules[0].Sources},
							"Rules[0].Destinations.#":         {nil, policy.Rules[0].Destinations},
							"Rules[0].SourceResource.ID":      {e2eResourceSubnetID(), policy.Rules[0].SourceResource.Id},
							"Rules[0].DestinationResource.ID": {e2eResourceDomainID(), policy.Rules[0].DestinationResource.Id},
							"Rules[0].PortRanges.#":           {int(1), len(*policy.Rules[0].PortRanges)},
							"Rules[0].PortRanges.0.Start":     {int(1000), (*policy.Rules[0].PortRanges)[0].Start},
							"Rules[0].PortRanges.0.End":       {int(2000), (*policy.Rules[0].PortRanges)[0].End},
						})
					},
				),
			},
		},
	})

}

func Test_Policy_Update_Groups(t *testing.T) {
	testE2E(t)
	rName := "po" + acctest.RandStringFromCharSet(10, acctest.CharSetAlpha)
	rNameFull := "netbird_policy." + rName
	var createdID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().Policies.Get, &createdID),
		Steps: []resource.TestStep{
			{
				ResourceName: rName,
				Config:       testPolicyResourceGroups(rName, rName, "desc", "accept", "udp", e2eGroupAllID(), e2eGroupNotAllID(), "443"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
				),
			},
			{
				ResourceName: rName,
				Config:       testPolicyResourceGroups(rName, rName, "desc-updated", "drop", "tcp", e2eGroupNotAllID(), e2eGroupAllID(), "80"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "name", rName),
					resource.TestCheckResourceAttr(rNameFull, "description", "desc-updated"),
					resource.TestCheckResourceAttr(rNameFull, "rule.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.action", "drop"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.ports.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.ports.0", "80"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.sources.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.sources.0", e2eGroupNotAllID()),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.destinations.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.destinations.0", e2eGroupAllID()),
					func(s *terraform.State) error {
						pID := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						policy, err := testClient().Policies.Get(context.Background(), pID)
						if err != nil {
							return err
						}
						return matchPairs(map[string][]any{
							"Name":                    {rName, policy.Name},
							"Description":             {"desc-updated", policy.Description},
							"Rules.#":                 {int(1), len(policy.Rules)},
							"Rules[0].Action":         {"drop", string(policy.Rules[0].Action)},
							"Rules[0].Sources.#":      {int(1), len(*policy.Rules[0].Sources)},
							"Rules[0].Sources.0":      {e2eGroupNotAllID(), (*policy.Rules[0].Sources)[0].Id},
							"Rules[0].Destinations.#": {int(1), len(*policy.Rules[0].Destinations)},
							"Rules[0].Destinations.0": {e2eGroupAllID(), (*policy.Rules[0].Destinations)[0].Id},
							"Rules[0].Ports.#":        {int(1), len(*policy.Rules[0].Ports)},
							"Rules[0].Ports.0":        {"80", (*policy.Rules[0].Ports)[0]},
						})
					},
				),
			},
		},
	})
}

func Test_Policy_Update_Resources(t *testing.T) {
	testE2E(t)
	rName := "po" + acctest.RandStringFromCharSet(10, acctest.CharSetAlpha)
	rNameFull := "netbird_policy." + rName
	var createdID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().Policies.Get, &createdID),
		Steps: []resource.TestStep{
			{
				ResourceName: rName,
				Config:       testPolicyResourceGroups(rName, rName, "desc", "accept", "udp", e2eGroupAllID(), e2eGroupNotAllID(), "80"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
				),
			},
			{
				ResourceName: rName,
				Config:       testPolicyResourceResources(rName, rName, "desc", "accept", "udp", e2eResourceSubnetID(), "subnet", e2eResourceDomainID(), "domain", "1", "100"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "name", rName),
					resource.TestCheckResourceAttr(rNameFull, "rule.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.action", "accept"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.ports.#", "0"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.sources.#", "0"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.source_resource.id", e2eResourceSubnetID()),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.source_resource.type", "subnet"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.destination_resource.id", e2eResourceDomainID()),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.destination_resource.type", "domain"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.destinations.#", "0"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.port_ranges.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.port_ranges.0.start", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.port_ranges.0.end", "100"),
					func(s *terraform.State) error {
						pID := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						policy, err := testClient().Policies.Get(context.Background(), pID)
						if err != nil {
							return err
						}
						return matchPairs(map[string][]any{
							"Name":                            {rName, policy.Name},
							"Description":                     {"desc", policy.Description},
							"Rules.#":                         {int(1), len(policy.Rules)},
							"Rules[0].Action":                 {"accept", string(policy.Rules[0].Action)},
							"Rules[0].Sources.#":              {nil, policy.Rules[0].Sources},
							"Rules[0].Destinations.#":         {nil, policy.Rules[0].Destinations},
							"Rules[0].SourceResource.ID":      {e2eResourceSubnetID(), policy.Rules[0].SourceResource.Id},
							"Rules[0].DestinationResource.ID": {e2eResourceDomainID(), policy.Rules[0].DestinationResource.Id},
							"Rules[0].PortRanges.#":           {int(1), len(*policy.Rules[0].PortRanges)},
							"Rules[0].PortRanges.0.Start":     {int(1), (*policy.Rules[0].PortRanges)[0].Start},
							"Rules[0].PortRanges.0.End":       {int(100), (*policy.Rules[0].PortRanges)[0].End},
						})
					},
				),
			},
		},
	})
}

// Leaving an Optional+Computed field out of the config adopts whatever the server
// holds. The policy PUT replaces the whole object, so an update that plans those
// fields as unknown and omits them wipes them; the plan has to carry the prior
// values instead, and show them.
func Test_Policy_Update_KeepsUnconfiguredFields(t *testing.T) {
	testE2E(t)
	rName := "po" + acctest.RandStringFromCharSet(10, acctest.CharSetAlpha)
	rNameFull := "netbird_policy." + rName
	pcNameFull := "netbird_posture_check." + rName
	var createdID string
	rule0 := tfjsonpath.New("rule").AtSliceIndex(0)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().Policies.Get, &createdID),
		Steps: []resource.TestStep{
			{
				Config: testPolicyResourceWith(rName, "desc", "accept",
					fmt.Sprintf(`source_posture_checks = [netbird_posture_check.%s.id]`, rName),
					fmt.Sprintf(`sources = [%q]
		destinations = [%q]
		ports = ["443"]`, e2eGroupAllID(), e2eGroupNotAllID())),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttrPair(rNameFull, "source_posture_checks.0", pcNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.ports.0", "443"),
				),
			},
			{
				// Only the description and the rule action are configured to
				// change; everything else is dropped from the config.
				Config: testPolicyResourceWith(rName, "desc-updated", "drop", "", ""),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						testExpectUpdateInPlace(rNameFull),
						plancheck.ExpectKnownValue(rNameFull, tfjsonpath.New("source_posture_checks"), knownvalue.ListSizeExact(1)),
						plancheck.ExpectKnownValue(rNameFull, rule0.AtMapKey("id"), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(rNameFull, rule0.AtMapKey("ports"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("443")})),
						plancheck.ExpectKnownValue(rNameFull, rule0.AtMapKey("sources"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(e2eGroupAllID())})),
						plancheck.ExpectKnownValue(rNameFull, rule0.AtMapKey("destinations"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(e2eGroupNotAllID())})),
						plancheck.ExpectKnownValue(rNameFull, rule0.AtMapKey("port_ranges"), knownvalue.Null()),
						plancheck.ExpectKnownValue(rNameFull, rule0.AtMapKey("source_resource"), knownvalue.Null()),
						plancheck.ExpectKnownValue(rNameFull, rule0.AtMapKey("destination_resource"), knownvalue.Null()),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rNameFull, "description", "desc-updated"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.action", "drop"),
					resource.TestCheckResourceAttrPair(rNameFull, "source_posture_checks.0", pcNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.ports.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.ports.0", "443"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.sources.0", e2eGroupAllID()),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.destinations.0", e2eGroupNotAllID()),
					func(s *terraform.State) error {
						pcID := s.RootModule().Resources[pcNameFull].Primary.Attributes["id"]
						policy, err := testClient().Policies.Get(context.Background(), createdID)
						if err != nil {
							return err
						}
						rule := policy.Rules[0]
						if rule.Ports == nil || rule.Sources == nil || rule.Destinations == nil {
							return fmt.Errorf("server dropped rule fields: ports=%v sources=%v destinations=%v",
								rule.Ports, rule.Sources, rule.Destinations)
						}
						if len(policy.SourcePostureChecks) != 1 || len(*rule.Ports) != 1 {
							return fmt.Errorf("server holds posture checks %v and ports %v, want one of each",
								policy.SourcePostureChecks, *rule.Ports)
						}
						return matchPairs(map[string][]any{
							"Description":             {"desc-updated", *policy.Description},
							"Rules[0].Action":         {"drop", string(rule.Action)},
							"SourcePostureChecks.0":   {pcID, policy.SourcePostureChecks[0]},
							"Rules[0].Ports.0":        {"443", (*rule.Ports)[0]},
							"Rules[0].Sources.#":      {1, len(*rule.Sources)},
							"Rules[0].Sources.0":      {e2eGroupAllID(), (*rule.Sources)[0].Id},
							"Rules[0].Destinations.#": {1, len(*rule.Destinations)},
							"Rules[0].Destinations.0": {e2eGroupNotAllID(), (*rule.Destinations)[0].Id},
						})
					},
				),
			},
			{
				ResourceName:      rNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// With omission meaning "keep", an explicit empty value is how
				// a field is cleared. The server reports it as absent, so this
				// also checks the empty value survives the apply.
				Config: testPolicyResourceWith(rName, "desc-updated", "drop",
					`source_posture_checks = []`, `ports = []`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rNameFull, "source_posture_checks.#", "0"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.ports.#", "0"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.sources.0", e2eGroupAllID()),
					func(s *terraform.State) error {
						policy, err := testClient().Policies.Get(context.Background(), createdID)
						if err != nil {
							return err
						}
						return matchPairs(map[string][]any{
							"SourcePostureChecks.#": {0, len(policy.SourcePostureChecks)},
							"Rules[0].Ports":        {nil, policy.Rules[0].Ports},
						})
					},
				),
			},
		},
	})
}

// authorized_groups is adopted like the other rule fields, but only while it is
// still valid: the server accepts it only on a netbird-ssh rule, so leaving that
// protocol plans it null rather than sending a request the server refuses.
func Test_Policy_Update_KeepsUnconfiguredAuthorizedGroups(t *testing.T) {
	testE2E(t)
	rName := "po" + acctest.RandStringFromCharSet(10, acctest.CharSetAlpha)
	rNameFull := "netbird_policy." + rName
	var createdID string
	agPath := tfjsonpath.New("rule").AtSliceIndex(0).AtMapKey("authorized_groups")
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().Policies.Get, &createdID),
		Steps: []resource.TestStep{
			{
				Config: testPolicyResourceSSH(rName, "netbird-ssh", "first", fmt.Sprintf(`{ %q = ["root"] }`, e2eGroupAllID())),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.authorized_groups."+e2eGroupAllID()+".0", "root"),
				),
			},
			{
				Config: testPolicyResourceSSH(rName, "netbird-ssh", "second", "null"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(rNameFull, agPath, knownvalue.MapExact(map[string]knownvalue.Check{
							e2eGroupAllID(): knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("root")}),
						})),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rNameFull, "rule.0.description", "second"),
					resource.TestCheckResourceAttr(rNameFull, "rule.0.authorized_groups."+e2eGroupAllID()+".0", "root"),
					func(s *terraform.State) error {
						policy, err := testClient().Policies.Get(context.Background(), createdID)
						if err != nil {
							return err
						}
						ag := policy.Rules[0].AuthorizedGroups
						if ag == nil {
							return fmt.Errorf("server dropped authorized_groups")
						}
						users := (*ag)[e2eGroupAllID()]
						if len(*ag) != 1 || len(users) != 1 || users[0] != "root" {
							return fmt.Errorf("server holds authorized_groups %v, want {%s: [root]}", *ag, e2eGroupAllID())
						}
						return nil
					},
				),
			},
			{
				ResourceName:      rNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testPolicyResourceSSH(rName, "netbird-ssh", "third", "{}"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rNameFull, "rule.0.authorized_groups.%", "0"),
					func(s *terraform.State) error {
						policy, err := testClient().Policies.Get(context.Background(), createdID)
						if err != nil {
							return err
						}
						return matchPairs(map[string][]any{
							"Rules[0].AuthorizedGroups": {nil, policy.Rules[0].AuthorizedGroups},
						})
					},
				),
			},
			{
				Config: testPolicyResourceSSH(rName, "netbird-ssh", "fourth", fmt.Sprintf(`{ %q = ["root"] }`, e2eGroupAllID())),
			},
			{
				Config: testPolicyResourceSSH(rName, "tcp", "fifth", "null"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(rNameFull, agPath, knownvalue.Null()),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rNameFull, "rule.0.protocol", "tcp"),
					resource.TestCheckNoResourceAttr(rNameFull, "rule.0.authorized_groups.%"),
					func(s *terraform.State) error {
						policy, err := testClient().Policies.Get(context.Background(), createdID)
						if err != nil {
							return err
						}
						return matchPairs(map[string][]any{
							"Rules[0].Protocol":         {"tcp", string(policy.Rules[0].Protocol)},
							"Rules[0].AuthorizedGroups": {nil, policy.Rules[0].AuthorizedGroups},
						})
					},
				),
			},
		},
	})
}

// testPolicyResourceWith is a tcp policy whose optional fields are exactly the
// HCL passed in, so a step can drop or clear them.
func testPolicyResourceWith(rName, description, action, policyHCL, ruleHCL string) string {
	return fmt.Sprintf(`resource "netbird_posture_check" "%[1]s" {
	name = "%[1]s"

	netbird_version_check {
		min_version = "0.40.0"
	}
}

resource "netbird_policy" "%[1]s" {
	name        = "%[1]s"
	description = "%[2]s"
	enabled     = true
	%[3]s

	rule {
		name     = "%[1]s"
		action   = "%[4]s"
		protocol = "tcp"
		%[5]s
	}
}`, rName, description, policyHCL, action, ruleHCL)
}

func testPolicyResourceSSH(rName, protocol, ruleDescription, authorizedGroups string) string {
	return fmt.Sprintf(`resource "netbird_policy" "%[1]s" {
	name    = "%[1]s"
	enabled = true

	rule {
		name              = "%[1]s"
		description       = "%[2]s"
		protocol          = "%[3]s"
		sources           = [%[4]q]
		destinations      = [%[5]q]
		authorized_groups = %[6]s
	}
}`, rName, ruleDescription, protocol, e2eGroupAllID(), e2eGroupNotAllID(), authorizedGroups)
}

func testPolicyResourceGroups(rName, name, description, rAction, rProt, rSource, rDest, port string) string {
	return fmt.Sprintf(`resource "netbird_policy" "%s" {
	name    = "%s"
	description = "%s"
	enabled = true

	rule {
		action        = "%s"
		bidirectional = true
		enabled       = true
		protocol      = "%s"
		name          = "%s"
		sources       = ["%s"]
		destinations  = ["%s"]
		ports         = ["%s"]
	}
}`, rName, name, description, rAction, rProt, name, rSource, rDest, port)
}

func testPolicyResourceResources(rName, name, description, rAction, rProt, rSourceID, rSourceType, rDestID, rDestType, pStart, pEnd string) string {
	return fmt.Sprintf(`resource "netbird_policy" "%s" {
	name        = "%s"
	description = "%s"
	enabled     = true

	rule {
		action                = "%s"
		bidirectional         = true
		enabled               = true
		protocol              = "%s"
		name                  = "%s"
		source_resource       = {
			id = "%s"
			type = "%s"
		}
		destination_resource  = {
			id = "%s"
			type = "%s"
		}
		port_ranges = [
			{
				start = %s
				end   = %s
			}
		]
	}
}`, rName, name, description, rAction, rProt, name, rSourceID, rSourceType, rDestID, rDestType, pStart, pEnd)
}
