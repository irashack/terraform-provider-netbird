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

func Test_Route_Create(t *testing.T) {
	testE2E(t)
	rName := "pc" + acctest.RandStringFromCharSet(10, acctest.CharSetAlpha)
	rNameFull := "netbird_route." + rName
	var createdID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().Routes.Get, &createdID),
		Steps: []resource.TestStep{
			{
				ResourceName: rName,
				Config:       testRouteResource(rName, e2eGroupAllID(), `null`, `desc`, `null`, `["example.com"]`, fmt.Sprintf("[%q]", e2eGroupNotAllID()), `null`),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "network_id", rName),
					resource.TestCheckResourceAttr(rNameFull, "groups.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "groups.0", e2eGroupAllID()),
					resource.TestCheckResourceAttr(rNameFull, "access_control_groups.#", "0"),
					resource.TestCheckResourceAttr(rNameFull, "description", "desc"),
					resource.TestCheckNoResourceAttr(rNameFull, "network"),
					resource.TestCheckResourceAttr(rNameFull, "domains.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "domains.0", "example.com"),
					resource.TestCheckResourceAttr(rNameFull, "peer_groups.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "peer_groups.0", e2eGroupNotAllID()),
					resource.TestCheckNoResourceAttr(rNameFull, "peer"),
					func(s *terraform.State) error {
						pID := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						route, err := testClient().Routes.Get(context.Background(), pID)
						if err != nil {
							return err
						}

						return matchPairs(map[string][]any{
							"network_id":            {rName, route.NetworkId},
							"groups.#":              {int(1), len(route.Groups)},
							"groups.0":              {e2eGroupAllID(), route.Groups[0]},
							"access_control_groups": {nil, route.AccessControlGroups},
							"description":           {"desc", route.Description},
							"domains.#":             {int(1), len(*route.Domains)},
							"domains.0":             {"example.com", (*route.Domains)[0]},
							"peer_groups.#":         {int(1), len(*route.PeerGroups)},
							"peer_groups.0":         {e2eGroupNotAllID(), (*route.PeerGroups)[0]},
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

func Test_Route_Update(t *testing.T) {
	testE2E(t)
	rName := "pc" + acctest.RandStringFromCharSet(10, acctest.CharSetAlpha)
	rNameFull := "netbird_route." + rName
	var createdID string
	// Resolved once, up front: the fixture helpers can fail the test, and doing
	// that from inside a Check closure aborts the run mid-apply, before
	// terraform-plugin-testing gets to its destroy step.
	peerID := testPeerID(t, "peer1")
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().Routes.Get, &createdID),
		Steps: []resource.TestStep{
			{
				ResourceName: rName,
				Config:       testRouteResource(rName, e2eGroupAllID(), `null`, `desc`, `null`, `["example.com"]`, fmt.Sprintf("[%q]", e2eGroupNotAllID()), `null`),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
				),
			},
			{
				ResourceName: rName,
				Config:       testRouteResource(rName, e2eGroupNotAllID(), fmt.Sprintf("[%q]", e2eGroupAllID()), `desc-updated`, `"100.10.0.0/16"`, `null`, `null`, fmt.Sprintf("%q", peerID)),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "network_id", rName),
					resource.TestCheckResourceAttr(rNameFull, "groups.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "groups.0", e2eGroupNotAllID()),
					resource.TestCheckResourceAttr(rNameFull, "access_control_groups.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "access_control_groups.0", e2eGroupAllID()),
					resource.TestCheckResourceAttr(rNameFull, "description", "desc-updated"),
					resource.TestCheckResourceAttr(rNameFull, "network", "100.10.0.0/16"),
					resource.TestCheckResourceAttr(rNameFull, "domains.#", "0"),
					resource.TestCheckResourceAttr(rNameFull, "peer_groups.#", "0"),
					resource.TestCheckResourceAttr(rNameFull, "peer", peerID),
					func(s *terraform.State) error {
						pID := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						route, err := testClient().Routes.Get(context.Background(), pID)
						if err != nil {
							return err
						}
						return matchPairs(map[string][]any{
							"network_id":              {rName, route.NetworkId},
							"groups.#":                {int(1), len(route.Groups)},
							"groups.0":                {e2eGroupNotAllID(), route.Groups[0]},
							"access_control_groups.#": {int(1), len(*route.AccessControlGroups)},
							"access_control_groups.0": {e2eGroupAllID(), (*route.AccessControlGroups)[0]},
							"description":             {"desc-updated", route.Description},
							"domains":                 {nil, route.Domains},
							"network":                 {"100.10.0.0/16", route.Network},
							"peer_group":              {nil, route.PeerGroups},
							"peer":                    {peerID, route.Peer},
						})
					},
				),
			},
		},
	})
}

// skip_auto_apply is Optional+Computed with no default, so leaving it out of the
// config adopts the server's value. The route PUT resets an omitted value to
// false, so the plan has to carry the prior value rather than leave it unknown.
func Test_Route_Update_KeepsUnconfiguredSkipAutoApply(t *testing.T) {
	testE2E(t)
	rName := "pc" + acctest.RandStringFromCharSet(10, acctest.CharSetAlpha)
	rNameFull := "netbird_route." + rName
	var createdID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().Routes.Get, &createdID),
		Steps: []resource.TestStep{
			{
				Config: testRouteResourceExitNode(rName, "desc", "true"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttr(rNameFull, "skip_auto_apply", "true"),
				),
			},
			{
				Config: testRouteResourceExitNode(rName, "desc-updated", "null"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						testExpectUpdateInPlace(rNameFull),
						plancheck.ExpectKnownValue(rNameFull, tfjsonpath.New("skip_auto_apply"), knownvalue.Bool(true)),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rNameFull, "description", "desc-updated"),
					resource.TestCheckResourceAttr(rNameFull, "skip_auto_apply", "true"),
					func(s *terraform.State) error {
						route, err := testClient().Routes.Get(context.Background(), createdID)
						if err != nil {
							return err
						}
						return matchPairs(map[string][]any{
							"description":     {"desc-updated", route.Description},
							"skip_auto_apply": {true, route.SkipAutoApply},
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

func testRouteResourceExitNode(rName, description, skipAutoApply string) string {
	return fmt.Sprintf(`resource "netbird_route" "%[1]s" {
  network_id      = "%[1]s"
  network         = "0.0.0.0/0"
  groups          = [%[2]q]
  peer_groups     = [%[3]q]
  description     = "%[4]s"
  skip_auto_apply = %[5]s
}
`, rName, e2eGroupAllID(), e2eGroupNotAllID(), description, skipAutoApply)
}

func testRouteResource(rName, groups, aclGroups, description, network, domains, peerGroups, peer string) string {
	return fmt.Sprintf(`resource "netbird_route" "%s" {
  network_id            = "%s"
  groups                = ["%s"]
  access_control_groups = %s
  description           = "%s"
  network               = %s
	domains               = %s
  peer_groups           = %s
	peer                  = %s
}
`, rName, rName, groups, aclGroups, description, network, domains, peerGroups, peer)
}
