CREATE TABLE IF NOT EXISTS `domain` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `active_mx` tinyint(1) NOT NULL DEFAULT 0,
  `active_ui` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS `dns_requests` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `target` varchar(253) NOT NULL,
  `type` enum('UI','EMAIL') NOT NULL,
  `status` varchar(16) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `activated_at` datetime NULL,
  `last_checked_at` datetime NULL,
  `next_check_at` datetime NULL,
  `last_check_result_json` text NULL,
  `fail_reason` text NULL,
  `expires_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_target_type` (`target`, `type`),
  KEY `idx_status` (`status`),
  KEY `idx_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS `domain_dns_rechecks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `domain_id` int(11) NOT NULL,
  `type` enum('UI','EMAIL') NOT NULL,
  `status` enum('OK','WARNING','DEGRADED','INVALID') NOT NULL DEFAULT 'OK',
  `consecutive_failures` int(11) NOT NULL DEFAULT 0,
  `last_checked_at` datetime NULL,
  `next_check_at` datetime NOT NULL,
  `last_ok_at` datetime NULL,
  `last_check_result_json` text NULL,
  `last_error` text NULL,
  `alert_status` enum('NONE','OPEN','RECOVERED','DISABLED') NOT NULL DEFAULT 'NONE',
  `alert_opened_at` datetime NULL,
  `last_alert_sent_at` datetime NULL,
  `next_alert_at` datetime NULL,
  `alert_sequence_count` int(11) NOT NULL DEFAULT 0,
  `first_invalid_result_json` text NULL,
  `last_valid_result_json` text NULL,
  `last_invalid_result_json` text NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_domain_recheck_type` (`domain_id`, `type`),
  KEY `idx_next_check_at` (`next_check_at`),
  KEY `idx_alert_status_next_alert_at` (`alert_status`, `next_alert_at`),
  CONSTRAINT `fk_domain_dns_rechecks_domain`
    FOREIGN KEY (`domain_id`) REFERENCES `domain` (`id`)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
