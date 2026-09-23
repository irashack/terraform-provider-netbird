//go:build e2e

package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

func Test_ReverseProxyClusters_DataSource(t *testing.T) {
	// A cluster only appears once a proxy has connected and is heartbeating, so
	// take one before asserting on the listing: without it the count is zero and
	// the assertion holds without proving anything.
	cluster := testRequireProxyCluster(t)
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testEnsureManagementRunning(t)
			// testRequireProxyCluster has already listed clusters and found an
			// online one, so the endpoint is known to work by the time this runs;
			// an error here is a real failure rather than an absent feature.
			if _, err := testClient().ReverseProxyClusters.List(context.Background()); err != nil {
				t.Fatalf("listing reverse proxy clusters: %v", err)
			}
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `data "netbird_reverse_proxy_clusters" "all" {}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.netbird_reverse_proxy_clusters.all", "clusters.#"),
					resource.TestCheckTypeSetElemNestedAttrs("data.netbird_reverse_proxy_clusters.all", "clusters.*", map[string]string{
						"address":           cluster.Address,
						"connected_proxies": "1",
					}),
				),
			},
		},
	})
}

func Test_ReverseProxyDomain_DataSource(t *testing.T) {
	// Free domains are not stored records: management derives one from every
	// online proxy cluster. So there is a free domain to look up only once a
	// proxy is connected, and its name is that cluster's address.
	cluster := testRequireProxyCluster(t)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `data "netbird_reverse_proxy_domain" "free" {
  type = "free"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.netbird_reverse_proxy_domain.free", "type", "free"),
					resource.TestCheckResourceAttr("data.netbird_reverse_proxy_domain.free", "validated", "true"),
					resource.TestCheckResourceAttr("data.netbird_reverse_proxy_domain.free", "domain", cluster.Address),
				),
			},
		},
	})
}

func Test_ReverseProxyDomain_CRUD(t *testing.T) {
	testE2E(t)
	cluster := testRequireProxyCluster(t)
	rName := "d" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domainName := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_domain." + rName

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			domains, err := testClient().ReverseProxyDomains.List(context.Background())
			if err != nil {
				return err
			}
			for _, d := range domains {
				if d.Domain == domainName {
					return fmt.Errorf("domain %s still exists after destroy", domainName)
				}
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyDomainResource(rName, domainName, cluster.Address),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "domain", domainName),
					resource.TestCheckResourceAttr(rNameFull, "target_cluster", cluster.Address),
					resource.TestCheckResourceAttr(rNameFull, "type", "custom"),
					func(s *terraform.State) error {
						domains, err := testClient().ReverseProxyDomains.List(context.Background())
						if err != nil {
							return err
						}
						id := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						for _, d := range domains {
							if d.Id == id {
								if d.Domain != domainName {
									return fmt.Errorf("domain mismatch: expected %s, got %s", domainName, d.Domain)
								}
								return nil
							}
						}
						return fmt.Errorf("domain %s not found in API", id)
					},
				),
			},
			{
				ResourceName:      rNameFull,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testReverseProxyDomainImportID(rNameFull),
			},
		},
	})
}

func Test_ReverseProxyService_DataSource(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	dsNameFull := "data.netbird_reverse_proxy_service.lookup"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create a service, then look it up by name via the data source
				Config: testReverseProxyServiceWithDataSource(rName, domain, testPeerID(t, "peer1")),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dsNameFull, "name", rName),
					resource.TestCheckResourceAttr(dsNameFull, "domain", domain),
					resource.TestCheckResourceAttr(dsNameFull, "enabled", "true"),
					resource.TestCheckResourceAttr(dsNameFull, "targets.#", "1"),
					resource.TestCheckResourceAttr(dsNameFull, "targets.0.port", "8080"),
					resource.TestCheckResourceAttr(dsNameFull, "targets.0.protocol", "http"),
					resource.TestCheckResourceAttrSet(dsNameFull, "id"),
					resource.TestCheckResourceAttrSet(dsNameFull, "auth.%"),
				),
			},
		},
	})
}

func Test_ReverseProxyService_PasswordAuth(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	peerID := testPeerID(t, "peer1")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			services, err := testClient().ReverseProxyServices.List(context.Background())
			if err != nil {
				return err
			}
			for _, svc := range services {
				if svc.Name == rName {
					return fmt.Errorf("service %s still exists", rName)
				}
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyServicePasswordAuth(rName, domain, peerID, "secret123"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "name", rName),
					resource.TestCheckResourceAttr(rNameFull, "domain", domain),
					resource.TestCheckResourceAttr(rNameFull, "enabled", "true"),
					resource.TestCheckResourceAttr(rNameFull, "targets.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.target_id", peerID),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.target_type", "peer"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.port", "8080"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.protocol", "http"),
					resource.TestCheckResourceAttr(rNameFull, "auth.password_auth.enabled", "true"),
					resource.TestCheckResourceAttr(rNameFull, "auth.password_auth.password", "secret123"),
					resource.TestCheckResourceAttrSet(rNameFull, "proxy_cluster"),
					func(s *terraform.State) error {
						id := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						svc, err := testClient().ReverseProxyServices.Get(context.Background(), id)
						if err != nil {
							return fmt.Errorf("get service: %w", err)
						}
						if svc.Name != rName {
							return fmt.Errorf("name mismatch: expected %s, got %s", rName, svc.Name)
						}
						if !svc.Enabled {
							return fmt.Errorf("expected service to be enabled")
						}
						if len(svc.Targets) != 1 {
							return fmt.Errorf("expected 1 target, got %d", len(svc.Targets))
						}
						if svc.Targets[0].TargetId != peerID {
							return fmt.Errorf("target_id mismatch")
						}
						if svc.Auth.PasswordAuth == nil || !svc.Auth.PasswordAuth.Enabled {
							return fmt.Errorf("expected password auth to be enabled")
						}
						return nil
					},
				),
			},
			{
				Config: testReverseProxyServicePasswordAuthUpdated(rName, domain, peerID, "newsecret456"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rNameFull, "enabled", "false"),
					resource.TestCheckResourceAttr(rNameFull, "auth.password_auth.password", "newsecret456"),
					resource.TestCheckResourceAttr(rNameFull, "pass_host_header", "true"),
					resource.TestCheckResourceAttr(rNameFull, "rewrite_redirects", "true"),
				),
			},
			{
				ResourceName:            rNameFull,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"auth.password_auth.password"},
			},
		},
	})
}

func Test_ReverseProxyService_PinAuth(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	var createdID string
	peerID := testPeerID(t, "peer1")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().ReverseProxyServices.Get, &createdID),
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyServicePinAuth(rName, domain, peerID, "9876"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "auth.pin_auth.enabled", "true"),
					resource.TestCheckResourceAttr(rNameFull, "auth.pin_auth.pin", "9876"),
					func(s *terraform.State) error {
						id := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						svc, err := testClient().ReverseProxyServices.Get(context.Background(), id)
						if err != nil {
							return fmt.Errorf("get service: %w", err)
						}
						if svc.Auth.PinAuth == nil || !svc.Auth.PinAuth.Enabled {
							return fmt.Errorf("expected pin auth to be enabled")
						}
						return nil
					},
				),
			},
		},
	})
}

func Test_ReverseProxyService_BearerAuth(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	var createdID string
	peerID := testPeerID(t, "peer1")
	groupID := e2eGroupAllID()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().ReverseProxyServices.Get, &createdID),
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyServiceBearerAuth(rName, domain, peerID, groupID),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "auth.bearer_auth.enabled", "true"),
					resource.TestCheckResourceAttr(rNameFull, "auth.bearer_auth.distribution_groups.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "auth.bearer_auth.distribution_groups.0", groupID),
					func(s *terraform.State) error {
						id := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						svc, err := testClient().ReverseProxyServices.Get(context.Background(), id)
						if err != nil {
							return fmt.Errorf("get service: %w", err)
						}
						if svc.Auth.BearerAuth == nil || !svc.Auth.BearerAuth.Enabled {
							return fmt.Errorf("expected bearer auth to be enabled")
						}
						if svc.Auth.BearerAuth.DistributionGroups == nil || len(*svc.Auth.BearerAuth.DistributionGroups) != 1 {
							return fmt.Errorf("expected 1 distribution group")
						}
						return nil
					},
				),
			},
		},
	})
}

func Test_ReverseProxyService_MultipleTargets(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	var createdID string
	peerID1 := testPeerID(t, "peer1")
	peerID2 := testPeerID(t, "peer2")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().ReverseProxyServices.Get, &createdID),
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyServiceMultiTarget(rName, domain, peerID1, peerID2),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "targets.#", "2"),
					func(s *terraform.State) error {
						id := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						svc, err := testClient().ReverseProxyServices.Get(context.Background(), id)
						if err != nil {
							return fmt.Errorf("get service: %w", err)
						}
						if len(svc.Targets) != 2 {
							return fmt.Errorf("expected 2 targets, got %d", len(svc.Targets))
						}
						return nil
					},
				),
			},
		},
	})
}

func Test_AccountSettings_PeerExpose(t *testing.T) {
	testE2E(t)
	groupID := e2eGroupAllID()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccountSettingsPeerExpose(true, groupID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("netbird_account_settings.test", "peer_expose_enabled", "true"),
					resource.TestCheckResourceAttr("netbird_account_settings.test", "peer_expose_groups.#", "1"),
					resource.TestCheckResourceAttr("netbird_account_settings.test", "peer_expose_groups.0", groupID),
				),
			},
			{
				Config: testAccountSettingsPeerExpose(false, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("netbird_account_settings.test", "peer_expose_enabled", "false"),
					resource.TestCheckResourceAttr("netbird_account_settings.test", "peer_expose_groups.#", "0"),
				),
			},
		},
	})
}

// --- Config helpers ---

func testReverseProxyDomainResource(rName, domain, cluster string) string {
	return fmt.Sprintf(`resource "netbird_reverse_proxy_domain" "%s" {
  domain         = %q
  target_cluster = %q
}`, rName, domain, cluster)
}

func testReverseProxyDomainImportID(rNameFull string) func(*terraform.State) (string, error) {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[rNameFull]
		if !ok {
			return "", fmt.Errorf("resource not found: %s", rNameFull)
		}
		return rs.Primary.Attributes["id"], nil
	}
}

func testReverseProxyServicePasswordAuth(rName, domain, peerID, password string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name    = %q
  domain  = %q
  enabled = true

  targets = [{
    target_id   = %q
    target_type = "peer"
    port        = 8080
    protocol    = "http"
  }]

  auth = {
    password_auth = {
      enabled  = true
      password = %q
    }
  }
}`, rName, rName, domain, peerID, password)
}

func testReverseProxyServicePasswordAuthUpdated(rName, domain, peerID, password string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name              = %q
  domain            = %q
  enabled           = false
  pass_host_header  = true
  rewrite_redirects = true

  targets = [{
    target_id   = %q
    target_type = "peer"
    port        = 8080
    protocol    = "http"
  }]

  auth = {
    password_auth = {
      enabled  = true
      password = %q
    }
  }
}`, rName, rName, domain, peerID, password)
}

func testReverseProxyServicePinAuth(rName, domain, peerID, pin string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name   = %q
  domain = %q

  targets = [{
    target_id   = %q
    target_type = "peer"
    port        = 80
    protocol    = "http"
  }]

  auth = {
    pin_auth = {
      enabled = true
      pin     = %q
    }
  }
}`, rName, rName, domain, peerID, pin)
}

func testReverseProxyServiceBearerAuth(rName, domain, peerID, groupID string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name   = %q
  domain = %q

  targets = [{
    target_id   = %q
    target_type = "peer"
    port        = 8080
    protocol    = "http"
  }]

  auth = {
    bearer_auth = {
      enabled             = true
      distribution_groups = [%q]
    }
  }
}`, rName, rName, domain, peerID, groupID)
}

func testReverseProxyServiceMultiTarget(rName, domain, peerID1, peerID2 string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name   = %q
  domain = %q

  targets = [
    {
      target_id   = %q
      target_type = "peer"
      port        = 8080
      protocol    = "http"
    },
    {
      target_id   = %q
      target_type = "peer"
      port        = 9090
      protocol    = "http"
    },
  ]

  auth = {
    password_auth = {
      enabled  = true
      password = "multitest"
    }
  }
}`, rName, rName, domain, peerID1, peerID2)
}

func testReverseProxyServiceWithDataSource(rName, domain, peerID string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "test" {
  name   = %q
  domain = %q

  targets = [{
    target_id   = %q
    target_type = "peer"
    port        = 8080
    protocol    = "http"
  }]

  auth = {
    link_auth = {
      enabled = true
    }
  }
}

data "netbird_reverse_proxy_service" "lookup" {
  name = netbird_reverse_proxy_service.test.name
}`, rName, domain, peerID)
}

func Test_ReverseProxyService_TargetOptions(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	peerID := testPeerID(t, "peer1")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testReverseProxyServiceDestroyed(rName),
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyServiceTargetOptions(rName, domain, peerID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "targets.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.protocol", "https"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.options.skip_tls_verify", "true"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.options.request_timeout", "30s"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.options.path_rewrite", "preserve"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.options.custom_headers.X-Custom", "test-value"),
					func(s *terraform.State) error {
						id := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						svc, err := testClient().ReverseProxyServices.Get(context.Background(), id)
						if err != nil {
							return fmt.Errorf("get service: %w", err)
						}
						if len(svc.Targets) != 1 {
							return fmt.Errorf("expected 1 target, got %d", len(svc.Targets))
						}
						opts := svc.Targets[0].Options
						if opts == nil {
							return fmt.Errorf("expected target options to be set")
						}
						if opts.SkipTlsVerify == nil || !*opts.SkipTlsVerify {
							return fmt.Errorf("expected skip_tls_verify to be true")
						}
						if opts.RequestTimeout == nil || *opts.RequestTimeout != "30s" {
							return fmt.Errorf("expected request_timeout to be 30s")
						}
						return nil
					},
				),
			},
			{
				ResourceName:            rNameFull,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"auth.password_auth.password"},
			},
		},
	})
}

func testReverseProxyServiceTargetOptions(rName, domain, peerID string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name   = %q
  domain = %q

  targets = [{
    target_id   = %q
    target_type = "peer"
    port        = 8443
    protocol    = "https"

    options = {
      skip_tls_verify = true
      request_timeout = "30s"
      path_rewrite    = "preserve"
      custom_headers = {
        "X-Custom" = "test-value"
      }
    }
  }]

  auth = {
    password_auth = {
      enabled  = true
      password = "options-test"
    }
  }
}`, rName, rName, domain, peerID)
}

func Test_ReverseProxyService_TCPMode(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	peerID := testPeerID(t, "peer1")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testReverseProxyServiceDestroyed(rName),
		Steps: []resource.TestStep{
			{
				// Durations use the canonical Go form ("1m0s", not "60s") so the
				// server's round-trip matches the config and import verification.
				Config: testReverseProxyServiceL4(rName, domain, peerID, "tcp", 15432, `
    options = {
      proxy_protocol  = true
      request_timeout = "1m0s"
    }`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "mode", "tcp"),
					resource.TestCheckResourceAttr(rNameFull, "listen_port", "15432"),
					resource.TestCheckResourceAttr(rNameFull, "port_auto_assigned", "false"),
					resource.TestCheckResourceAttr(rNameFull, "targets.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.protocol", "tcp"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.options.proxy_protocol", "true"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.options.request_timeout", "1m0s"),
					func(s *terraform.State) error {
						id := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						svc, err := testClient().ReverseProxyServices.Get(context.Background(), id)
						if err != nil {
							return fmt.Errorf("get service: %w", err)
						}
						if svc.Mode == nil || *svc.Mode != "tcp" {
							return fmt.Errorf("expected mode tcp, got %v", svc.Mode)
						}
						if svc.ListenPort == nil || *svc.ListenPort != 15432 {
							return fmt.Errorf("expected listen_port 15432, got %v", svc.ListenPort)
						}
						if len(svc.Targets) != 1 {
							return fmt.Errorf("expected 1 target, got %d", len(svc.Targets))
						}
						opts := svc.Targets[0].Options
						if opts == nil || opts.ProxyProtocol == nil || !*opts.ProxyProtocol {
							return fmt.Errorf("expected proxy_protocol to be true")
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
		},
	})
}

func Test_ReverseProxyService_UDPMode(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	peerID := testPeerID(t, "peer1")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testReverseProxyServiceDestroyed(rName),
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyServiceL4(rName, domain, peerID, "udp", 19053, `
    options = {
      session_idle_timeout = "2m0s"
    }`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "mode", "udp"),
					resource.TestCheckResourceAttr(rNameFull, "listen_port", "19053"),
					resource.TestCheckResourceAttr(rNameFull, "targets.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.protocol", "udp"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.options.session_idle_timeout", "2m0s"),
					func(s *terraform.State) error {
						id := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						svc, err := testClient().ReverseProxyServices.Get(context.Background(), id)
						if err != nil {
							return fmt.Errorf("get service: %w", err)
						}
						if svc.Mode == nil || *svc.Mode != "udp" {
							return fmt.Errorf("expected mode udp, got %v", svc.Mode)
						}
						if len(svc.Targets) != 1 {
							return fmt.Errorf("expected 1 target, got %d", len(svc.Targets))
						}
						opts := svc.Targets[0].Options
						if opts == nil || opts.SessionIdleTimeout == nil || *opts.SessionIdleTimeout != "2m0s" {
							return fmt.Errorf("expected session_idle_timeout 2m0s, got %v", opts)
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
		},
	})
}

func testReverseProxyServiceDestroyed(name string) func(*terraform.State) error {
	return func(s *terraform.State) error {
		services, err := testClient().ReverseProxyServices.List(context.Background())
		if err != nil {
			return err
		}
		for _, svc := range services {
			if svc.Name == name {
				return fmt.Errorf("service %s still exists", name)
			}
		}
		return nil
	}
}

func testReverseProxyServiceL4(rName, domain, peerID, mode string, listenPort int, options string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name        = %q
  domain      = %q
  mode        = %q
  listen_port = %d

  targets = [{
    target_id   = %q
    target_type = "peer"
    port        = 5001
    protocol    = %q
%s
  }]

  auth = {}
}`, rName, rName, domain, mode, listenPort, peerID, mode, options)
}

func Test_ReverseProxyService_HeaderAuth(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	peerID := testPeerID(t, "peer1")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testReverseProxyServiceDestroyed(rName),
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyServiceHeaderAuth(rName, domain, peerID, "X-API-Key", "my-secret-key"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "auth.header_auths.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "auth.header_auths.0.enabled", "true"),
					resource.TestCheckResourceAttr(rNameFull, "auth.header_auths.0.header", "X-API-Key"),
					resource.TestCheckResourceAttr(rNameFull, "auth.header_auths.0.value", "my-secret-key"),
					func(s *terraform.State) error {
						id := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						svc, err := testClient().ReverseProxyServices.Get(context.Background(), id)
						if err != nil {
							return fmt.Errorf("get service: %w", err)
						}
						if svc.Auth.HeaderAuths == nil || len(*svc.Auth.HeaderAuths) != 1 {
							return fmt.Errorf("expected 1 header auth")
						}
						h := (*svc.Auth.HeaderAuths)[0]
						if !h.Enabled || h.Header != "X-API-Key" {
							return fmt.Errorf("header auth mismatch")
						}
						return nil
					},
				),
			},
			{
				ResourceName:            rNameFull,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"auth.header_auths.0.value"},
			},
		},
	})
}

func Test_ReverseProxyService_AccessRestrictions(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	peerID := testPeerID(t, "peer1")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testReverseProxyServiceDestroyed(rName),
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyServiceAccessRestrictions(rName, domain, peerID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(rNameFull, "id"),
					resource.TestCheckResourceAttr(rNameFull, "access_restrictions.allowed_countries.#", "2"),
					resource.TestCheckResourceAttr(rNameFull, "access_restrictions.allowed_countries.0", "US"),
					resource.TestCheckResourceAttr(rNameFull, "access_restrictions.allowed_countries.1", "DE"),
					resource.TestCheckResourceAttr(rNameFull, "access_restrictions.blocked_cidrs.#", "1"),
					resource.TestCheckResourceAttr(rNameFull, "access_restrictions.blocked_cidrs.0", "192.168.0.0/16"),
					func(s *terraform.State) error {
						id := s.RootModule().Resources[rNameFull].Primary.Attributes["id"]
						svc, err := testClient().ReverseProxyServices.Get(context.Background(), id)
						if err != nil {
							return fmt.Errorf("get service: %w", err)
						}
						if svc.AccessRestrictions == nil {
							return fmt.Errorf("expected access restrictions")
						}
						if svc.AccessRestrictions.AllowedCountries == nil || len(*svc.AccessRestrictions.AllowedCountries) != 2 {
							return fmt.Errorf("expected 2 allowed countries")
						}
						if svc.AccessRestrictions.BlockedCidrs == nil || len(*svc.AccessRestrictions.BlockedCidrs) != 1 {
							return fmt.Errorf("expected 1 blocked CIDR")
						}
						return nil
					},
				),
			},
			{
				ResourceName:            rNameFull,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"auth.password_auth.password"},
			},
		},
	})
}

func testReverseProxyServiceHeaderAuth(rName, domain, peerID, header, value string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name   = %q
  domain = %q

  targets = [{
    target_id   = %q
    target_type = "peer"
    port        = 8080
    protocol    = "http"
  }]

  auth = {
    header_auths = [{
      enabled = true
      header  = %q
      value   = %q
    }]
  }
}`, rName, rName, domain, peerID, header, value)
}

func testReverseProxyServiceAccessRestrictions(rName, domain, peerID string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name   = %q
  domain = %q

  targets = [{
    target_id   = %q
    target_type = "peer"
    port        = 8080
    protocol    = "http"
  }]

  auth = {
    password_auth = {
      enabled  = true
      password = "test123"
    }
  }

  access_restrictions = {
    allowed_countries = ["US", "DE"]
    blocked_cidrs     = ["192.168.0.0/16"]
  }
}`, rName, rName, domain, peerID)
}

func testAccountSettingsPeerExpose(enabled bool, groupID string) string {
	groups := "[]"
	if groupID != "" {
		groups = fmt.Sprintf("[%q]", groupID)
	}
	return fmt.Sprintf(`resource "netbird_account_settings" "test" {
  peer_expose_enabled = %t
  peer_expose_groups  = %s
}`, enabled, groups)
}

// A cluster target names the proxy cluster itself and has the proxy dial the
// upstream directly. Management refuses one without direct_upstream, so this is
// also the test that the option reaches the server at all.
func Test_ReverseProxyService_ClusterTarget(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	var createdID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().ReverseProxyServices.Get, &createdID),
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyServiceClusterTarget(rName, domain, cluster.Address),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.target_type", "cluster"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.target_id", cluster.Address),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.host", "host.docker.internal"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.options.direct_upstream", "true"),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.options.path_rewrite", "preserve"),
					func(s *terraform.State) error {
						svc, err := testClient().ReverseProxyServices.Get(context.Background(), createdID)
						if err != nil {
							return fmt.Errorf("get service: %w", err)
						}
						if len(svc.Targets) != 1 {
							return fmt.Errorf("expected 1 target, got %d", len(svc.Targets))
						}
						tgt := svc.Targets[0]
						return matchPairs(map[string][]any{
							"TargetType":             {api.ServiceTargetTargetTypeCluster, tgt.TargetType},
							"TargetId":               {cluster.Address, tgt.TargetId},
							"Host":                   {"host.docker.internal", valOr(tgt.Host, "")},
							"Options.DirectUpstream": {true, tgt.Options != nil && valOr(tgt.Options.DirectUpstream, false)},
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

func testReverseProxyServiceClusterTarget(rName, domain, clusterAddress string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name   = %q
  domain = %q

  targets = [{
    target_id   = %q
    target_type = "cluster"
    host        = "host.docker.internal"
    port        = 8096
    protocol    = "http"
    path        = "/"

    options = {
      direct_upstream = true
      path_rewrite    = "preserve"
    }
  }]

  auth = {}
}`, rName, rName, domain, clusterAddress)
}

// The harness proxy runs without CrowdSec, so the cluster reports no support
// and nothing enforces the mode. What this covers is the part the provider
// owns: management stores the mode whatever the cluster supports, and it has to
// come back unchanged through create, update and import.
func Test_ReverseProxyService_CrowdsecMode(t *testing.T) {
	cluster := testRequireProxyCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	peerID := testPeerID(t, "peer1")
	var createdID string

	serverMode := func(want string) resource.TestCheckFunc {
		return func(*terraform.State) error {
			svc, err := testClient().ReverseProxyServices.Get(context.Background(), createdID)
			if err != nil {
				return fmt.Errorf("get service: %w", err)
			}
			if svc.AccessRestrictions == nil || svc.AccessRestrictions.CrowdsecMode == nil {
				return fmt.Errorf("server holds no crowdsec_mode, want %q", want)
			}
			if got := string(*svc.AccessRestrictions.CrowdsecMode); got != want {
				return fmt.Errorf("server crowdsec_mode = %q, want %q", got, want)
			}
			return nil
		}
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().ReverseProxyServices.Get, &createdID),
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyServiceCrowdsec(rName, domain, peerID, "observe"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttr(rNameFull, "access_restrictions.crowdsec_mode", "observe"),
					serverMode("observe"),
				),
			},
			{
				Config:           testReverseProxyServiceCrowdsec(rName, domain, peerID, "enforce"),
				ConfigPlanChecks: updatesInPlace(rNameFull),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rNameFull, "access_restrictions.crowdsec_mode", "enforce"),
					serverMode("enforce"),
				),
			},
			{
				ResourceName:            rNameFull,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"auth.password_auth.password"},
			},
		},
	})
}

func testReverseProxyServiceCrowdsec(rName, domain, peerID, mode string) string {
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name   = %q
  domain = %q

  targets = [{
    target_id   = %q
    target_type = "peer"
    port        = 8080
    protocol    = "http"
  }]

  auth = {
    password_auth = {
      enabled  = true
      password = "crowdsec-test"
    }
  }

  access_restrictions = {
    crowdsec_mode = %q
  }
}`, rName, rName, domain, peerID, mode)
}

// testRequirePrivateCluster returns the harness cluster after checking it
// claims the private capability. The harness proxy runs with NB_PROXY_PRIVATE,
// so a cluster without it is a broken fixture, not a deployment to skip.
func testRequirePrivateCluster(t *testing.T) api.ProxyCluster {
	t.Helper()
	cluster := testRequireProxyCluster(t)
	if cluster.Private == nil || !*cluster.Private {
		t.Fatalf("proxy cluster %s does not report the private capability (private = %v)", cluster.Address, cluster.Private)
	}
	return cluster
}

// testCheckPrivateService asserts the server holds the NetBird-only service the
// configuration describes, which is what an update that drops a field would
// silently change.
func testCheckPrivateService(id *string, clusterAddress string, passHostHeader bool, groups ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		svc, err := testClient().ReverseProxyServices.Get(context.Background(), *id)
		if err != nil {
			return fmt.Errorf("get service: %w", err)
		}
		if svc.AccessGroups == nil || !slices.Equal(*svc.AccessGroups, groups) {
			return fmt.Errorf("server access_groups = %v, want %v", svc.AccessGroups, groups)
		}
		if len(svc.Targets) != 1 {
			return fmt.Errorf("expected 1 target, got %d", len(svc.Targets))
		}
		tgt := svc.Targets[0]
		return matchPairs(map[string][]any{
			"Private":                {true, valOr(svc.Private, false)},
			"Mode":                   {api.ServiceModeHttp, valOr(svc.Mode, "")},
			"PassHostHeader":         {passHostHeader, valOr(svc.PassHostHeader, false)},
			"Target.TargetType":      {api.ServiceTargetTargetTypeCluster, tgt.TargetType},
			"Target.TargetId":        {clusterAddress, tgt.TargetId},
			"Target.Host":            {"host.docker.internal", valOr(tgt.Host, "")},
			"Target.Path":            {"/", valOr(tgt.Path, "")},
			"Target.DirectUpstream":  {true, tgt.Options != nil && valOr(tgt.Options.DirectUpstream, false)},
			"Target.PathRewriteMode": {api.ServiceTargetOptionsPathRewritePreserve, valOr(valOr(tgt.Options, api.ServiceTargetOptions{}).PathRewrite, "")},
		})
	}
}

// A private service in the shape the dashboard creates: NetBird-only, reached
// by two groups, pointing at the proxy cluster and dialling a sidecar on the
// proxy host. The update step changes one unrelated field, which is how the
// service used to be turned public: the PUT replaces the whole service and
// private and access_groups were never sent.
func Test_ReverseProxyService_Private(t *testing.T) {
	cluster := testRequirePrivateCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	groupA, groupB := e2eGroupAllID(), e2eGroupNotAllID()
	var createdID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().ReverseProxyServices.Get, &createdID),
		Steps: []resource.TestStep{
			{
				Config: testReverseProxyServicePrivate(rName, domain, cluster.Address, true, groupA, groupB),
				Check: resource.ComposeAggregateTestCheckFunc(
					testRecordID(rNameFull, &createdID),
					resource.TestCheckResourceAttr(rNameFull, "private", "true"),
					resource.TestCheckResourceAttr(rNameFull, "access_groups.#", "2"),
					resource.TestCheckResourceAttr(rNameFull, "access_groups.0", groupA),
					resource.TestCheckResourceAttr(rNameFull, "access_groups.1", groupB),
					resource.TestCheckResourceAttr(rNameFull, "targets.0.options.direct_upstream", "true"),
					testCheckPrivateService(&createdID, cluster.Address, true, groupA, groupB),
				),
			},
			{
				Config:           testReverseProxyServicePrivate(rName, domain, cluster.Address, false, groupA, groupB),
				ConfigPlanChecks: updatesInPlace(rNameFull),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rNameFull, "pass_host_header", "false"),
					resource.TestCheckResourceAttr(rNameFull, "private", "true"),
					testCheckPrivateService(&createdID, cluster.Address, false, groupA, groupB),
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

// The adoption path for services that already exist: import one created
// outside Terraform, then plan with a configuration declaring what it holds.
// The plan must be empty, and a later update must leave it private.
func Test_ReverseProxyService_PrivateImportThenPlan(t *testing.T) {
	cluster := testRequirePrivateCluster(t)
	rName := "s" + acctest.RandStringFromCharSet(8, acctest.CharSetAlpha)
	domain := rName + "." + cluster.Address
	rNameFull := "netbird_reverse_proxy_service." + rName
	groupA, groupB := e2eGroupAllID(), e2eGroupNotAllID()
	var id string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testEnsureManagementRunning(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testCheckGone(testClient().ReverseProxyServices.Get, &id),
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					mode := api.ServiceRequestMode(api.ServiceModeHttp)
					preserve := api.ServiceTargetOptionsPathRewritePreserve
					svc, err := testClient().ReverseProxyServices.Create(context.Background(), api.ServiceRequest{
						Name:             rName,
						Domain:           domain,
						Enabled:          true,
						Mode:             &mode,
						PassHostHeader:   valPtr(true),
						RewriteRedirects: valPtr(false),
						Private:          valPtr(true),
						AccessGroups:     &[]string{groupA, groupB},
						Auth:             &api.ServiceAuthConfig{},
						Targets: &[]api.ServiceTarget{{
							TargetId:   cluster.Address,
							TargetType: api.ServiceTargetTargetTypeCluster,
							Host:       valPtr("host.docker.internal"),
							Port:       8096,
							Protocol:   api.ServiceTargetProtocolHttp,
							Path:       valPtr("/"),
							Enabled:    true,
							Options: &api.ServiceTargetOptions{
								DirectUpstream: valPtr(true),
								PathRewrite:    &preserve,
							},
						}},
					})
					if err != nil {
						t.Fatalf("could not create the service to import: %v", err)
					}
					id = svc.Id
				},
				Config:             testReverseProxyServicePrivate(rName, domain, cluster.Address, true, groupA, groupB),
				ResourceName:       rNameFull,
				ImportState:        true,
				ImportStatePersist: true,
				ImportStateIdFunc:  func(*terraform.State) (string, error) { return id, nil },
			},
			{
				Config:   testReverseProxyServicePrivate(rName, domain, cluster.Address, true, groupA, groupB),
				PlanOnly: true,
			},
			{
				Config:           testReverseProxyServicePrivate(rName, domain, cluster.Address, false, groupA, groupB),
				ConfigPlanChecks: updatesInPlace(rNameFull),
				Check:            testCheckPrivateService(&id, cluster.Address, false, groupA, groupB),
			},
		},
	})
}

func testReverseProxyServicePrivate(rName, domain, clusterAddress string, passHostHeader bool, groups ...string) string {
	quoted := make([]string, len(groups))
	for i, g := range groups {
		quoted[i] = fmt.Sprintf("%q", g)
	}
	return fmt.Sprintf(`
resource "netbird_reverse_proxy_service" "%s" {
  name              = %q
  domain            = %q
  mode              = "http"
  private           = true
  access_groups     = [%s]
  pass_host_header  = %t
  rewrite_redirects = false

  targets = [{
    target_id   = %q
    target_type = "cluster"
    host        = "host.docker.internal"
    port        = 8096
    protocol    = "http"
    path        = "/"

    options = {
      direct_upstream = true
      path_rewrite    = "preserve"
    }
  }]

  auth = {}
}`, rName, rName, domain, strings.Join(quoted, ", "), passHostHeader, clusterAddress)
}
