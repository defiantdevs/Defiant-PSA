IAT<!-- Main Sidebar Container -->
<aside class="main-sidebar sidebar-dark-<?php echo nullable_htmlentities($config_theme); ?> d-print-none">

        <a class="brand-link" href="dashboard.php">
     <div class="brand-image" style="height: 300px;">
    <img alt="<?=nullable_htmlentities($company_name)?> logo" class="img-fluid" style="max-width: 100%; height: 100%;" src="<?php echo !empty($company_logo) ? "./uploads/settings/$company_logo" : "./uploads/settings/wwt-white.png"; ?>">
</div>
    </a>
    
    <!-- Sidebar -->
    <div class="sidebar">

        <!-- Sidebar Menu -->
        <nav>
            <ul class="nav nav-pills nav-sidebar flex-column mt-3" data-widget="treeview" data-accordion="false">
                <li class="nav-item">
                    <a href="dashboard.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "dashboard.php") { echo "active"; } ?>">
                        <i class="nav-icon fas fa-tachometer-alt"></i>
                        <p>Dashboard</p>
                    </a>
                </li>
                <?php if (lookupUserPermission("module_client") >= 1) { ?>
                    <li class="nav-item">
                        <a href="clients.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "clients.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-users"></i>
                            <p>
                                Clients
                                <?php if ($num_active_clients) { ?>
                                    <span class="right badge text-light"><?php echo $num_active_clients; ?></span>
                                <?php } ?>
                            </p>
                        </a>
                    </li>
                <?php } ?>

                <?php if (lookupUserPermission("module_support") >= 1) { ?>
                    <?php if ($config_module_enable_ticketing == 1) { ?>
                        <li class="nav-header mt-3">SUPPORT</li>
                        <li class="nav-item">
                            <a href="tickets.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "tickets.php" || basename($_SERVER["PHP_SELF"]) == "ticket.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-life-ring"></i>
                                <p>
                                    Tickets
                                    <?php if ($num_active_tickets) { ?>
                                        <span class="right badge text-light"><?php echo $num_active_tickets; ?></span>
                                    <?php } ?>
                                </p>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="recurring_tickets.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "recurring_tickets.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-redo-alt"></i>
                                <p>
                                    Recurring Tickets
                                    <?php if ($num_recurring_tickets) { ?>
                                        <span class="right badge text-light"><?php echo $num_recurring_tickets; ?></span>
                                    <?php } ?>
                                </p>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="projects.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "projects.php" || basename($_SERVER["PHP_SELF"]) == "project_details.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-project-diagram"></i>
                                <p>
                                    Projects
                                    <?php if ($num_active_projects) { ?>
                                        <span class="right badge text-light"><?php echo $num_active_projects; ?></span>
                                    <?php } ?>
                                </p>
                            </a>
                        </li>
                    <?php } ?>
                <?php } ?>

                <li class="nav-item">
                    <a href="calendar_events.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "calendar_events.php") { echo "active"; } ?>">
                        <i class="nav-icon fas fa-calendar-alt"></i>
                        <p>Calendar</p>
                    </a>
                </li>
                <?php if ($config_module_enable_accounting == 1 && lookupUserPermission("module_sales") >= 1) { ?>
                    <li class="nav-header mt-3">BILLING</li>
                    <li class="nav-item">
                        <a href="quotes.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "quotes.php" || basename($_SERVER["PHP_SELF"]) == "quote.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-comment-dollar"></i>
                            <p>
                                Quotes
                                <?php if ($num_open_quotes) { ?>
                                    <span class="right badge text-light"><?php echo $num_open_quotes; ?></span>
                                <?php } ?>
                            </p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="invoices.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "invoices.php" || basename($_SERVER["PHP_SELF"]) == "invoice.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-file-invoice"></i>
                            <p>
                                Invoices
                                <?php if ($num_open_invoices) { ?>
                                    <span class="right badge text-light"><?php echo $num_open_invoices; ?></span>
                                <?php } ?>
                            </p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="recurring_invoices.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "recurring_invoices.php" || basename($_SERVER["PHP_SELF"]) == "recurring_invoices.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-redo-alt"></i>
                            <p>
                                Recurring Invoices
                                <?php if ($num_recurring_invoices) { ?>
                                    <span class="right badge text-light"><?php echo $num_recurring_invoices; ?></span>
                                <?php } ?>
                            </p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="revenues.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "revenues.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-hand-holding-usd"></i>
                            <p>Revenues</p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="products.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "products.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-box-open"></i>
                            <p>Products</p>
                        </a>
                    </li>
                <?php } ?>
                <?php if ($config_module_enable_accounting == 1 && lookupUserPermission("module_financial") >= 1) { ?>
                    <li class="nav-header mt-3">FINANCE</li>
                    <li class="nav-item">
                        <a href="payments.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "payments.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-credit-card"></i>
                            <p>Payments</p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="vendors.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "vendors.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-building"></i>
                            <p>Vendors</p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="expenses.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "expenses.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-shopping-cart"></i>
                            <p>Expenses</p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="recurring_expenses.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "recurring_expenses.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-redo-alt"></i>
                            <p>
                                Recurring Expenses
                                <?php if ($num_recurring_expenses) { ?>
                                    <span class="right badge text-light"><?php echo $num_recurring_expenses; ?></span>
                                <?php } ?>
                            </p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="accounts.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "accounts.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-piggy-bank"></i>
                            <p>Accounts</p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="transfers.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "transfers.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-exchange-alt"></i>
                            <p>Transfers</p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="budget.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "budget.php" || basename($_SERVER["PHP_SELF"]) == "budget_edit.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-balance-scale"></i>
                            <p>Budget</p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="trips.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "trips.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-route"></i>
                            <p>Trips</p>
                        </a>
                    </li>
                <?php } ?>

                <?php if (lookupUserPermission("module_reporting") >= 1) { ?>
                    <li class="nav-item mt-3">
                        <a href="report_income_summary.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "report_income_summary.php") { echo "active"; } ?>">
                            <i class="fas fa-chart-line nav-icon"></i>
                            <p>Reports</p>
                            <i class="fas fa-angle-right nav-icon float-right"></i>
                        </a>
                    </li>
                <?php } ?>

                <?php
                $sql_custom_links = mysqli_query($mysqli, "SELECT * FROM custom_links WHERE custom_link_location = 1 AND custom_link_archived_at IS NULL ORDER BY custom_link_order ASC, custom_link_name ASC");
                while ($row = mysqli_fetch_array($sql_custom_links)) {
                    $custom_link_name = nullable_htmlentities($row['custom_link_name']);
                    $custom_link_uri = nullable_htmlentities($row['custom_link_uri']);
                    $custom_link_icon = nullable_htmlentities($row['custom_link_icon']);
                    $custom_link_new_tab = intval($row['custom_link_new_tab']);
                    if ($custom_link_new_tab == 1) {
                        $target = "target='_blank' rel='noopener noreferrer'";
                    } else {
                        $target = "";
                    }
                    ?>
                    <li class="nav-item">
                        <a href="<?php echo $custom_link_uri; ?>" <?php echo $target; ?> class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == basename($custom_link_uri)) { echo "active"; } ?>">
                            <i class="fas fa-<?php echo $custom_link_icon; ?> nav-icon"></i>
                            <p><?php echo $custom_link_name; ?></p>
                            <i class="fas fa-angle-right nav-icon float-right"></i>
                        </a>
                    </li>
                <?php } ?>
            </ul>
        </nav>
        <!-- /.sidebar-menu -->
        <div class="mb-3"></div>
    </div>
    <!-- /.sidebar -->
</aside>
