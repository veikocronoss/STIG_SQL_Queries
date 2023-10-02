SELECT 'V-214028' AS [VULNERABILITY_ID], 'SQL6-D0-016200' AS [RULE_ID],
       CASE WHEN is_disabled_value = 1 THEN 'Not a finding' ELSE 'OPEN' END AS [FINDING_STATUS],
       CASE WHEN is_disabled_value = 1 THEN '1' ELSE '0' END AS [CONFIG_VALUE],
       CASE WHEN is_disabled_value = 1 THEN '[sa] account disabled' ELSE '[sa] account enabled' END AS [NOTES]
FROM (SELECT CAST((SELECT is_disabled FROM sys.sql_logins WHERE principal_id = 1) AS INT) AS is_disabled_value) AS subquery



UNION ALL



SELECT 'V-213964' AS [VULNERABILITY_ID], 'SQL6-D0-007900' AS [RULE_ID],
       CASE WHEN authentication_mode = 'Windows Authentication' THEN 'Not a finding'
            ELSE CASE WHEN EXISTS (SELECT * FROM sys.sql_logins WHERE [name] NOT IN ('sa', '##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##') AND is_expiration_checked = 0 OR is_policy_checked = 0) THEN 'OPEN' ELSE 'Not a finding' END END AS [FINDING_STATUS],
       CASE WHEN authentication_mode = 'Windows Authentication' THEN 'Windows Authentication mode' ELSE 'Password Complexity and Lifetime Rules' END AS [CONFIG_VALUE],
       CASE WHEN authentication_mode = 'Windows Authentication' THEN 'SQL Server is using Windows Authentication mode'
            ELSE CASE WHEN EXISTS (SELECT * FROM sys.sql_logins WHERE [name] NOT IN ('sa', '##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##') AND is_expiration_checked = 0 OR is_policy_checked = 0) THEN 'Accounts do not have both "is_expiration_checked" and "is_policy_checked" equal to "1"'
                      ELSE NULL END END AS [NOTES]
FROM (SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly') WHEN 1 THEN 'Windows Authentication' WHEN 0 THEN 'SQL Server Authentication' END AS authentication_mode) AS subquery



UNION ALL



SELECT 'V-214045' AS [VULNERABILITY_ID], 'SQL6-D0-018100' AS [RULE_ID],
       CASE WHEN authentication_mode = '1' THEN 'Not a finding' ELSE 'OPEN' END AS [FINDING_STATUS],
       CASE WHEN authentication_mode = '1' THEN 'Windows NT Authentication' ELSE 'Check system documentation for SQL Server authentication' END AS [CONFIG_VALUE],
       CASE WHEN authentication_mode = '1' THEN 'SQL Server uses Windows NT Authentication' ELSE 'Check system documentation' END AS [NOTES]
FROM (SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS VARCHAR(50)) AS authentication_mode) AS subquery



UNION ALL



SELECT 'V-214046' AS [VULNERABILITY_ID], 'SQL6-D0-018200' AS [RULE_ID],
       CASE WHEN COUNT(*) > 0 THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],
       NULL AS [CONFIG_VALUE],
       CASE WHEN COUNT(*) > 0 THEN 'Check application documentation for obfuscation of authentication data' ELSE 'No applications found that allow for entry of account name and password, or PIN' END AS [NOTES]
FROM sys.dm_exec_connections
WHERE session_id > 50
  AND client_net_address <> '<local machine>'
  AND protocol_type = 'TCP'
  AND auth_scheme <> 'NTLM'



UNION ALL



SELECT 'V-213930' AS [VULNERABILITY_ID], 'SQL6-D0-003700' AS [RULE_ID],
       CASE WHEN SERVERPROPERTY('IsIntegratedSecurityOnly') = 1 THEN 'Not a finding' ELSE 'OPEN' END AS [FINDING_STATUS],
	   CASE WHEN SERVERPROPERTY('IsIntegratedSecurityOnly') = 1 THEN 'Windows Authentication' ELSE 'Mixed Mode' END AS [CONFIG_VALUE],
       CASE WHEN SERVERPROPERTY('IsIntegratedSecurityOnly') = 1 THEN 'No further action required.' ELSE 'Mixed mode authentication is in use. Refer to System Documentation for remediation steps.' END AS [NOTES]



UNION ALL



SELECT 'V-214008' AS [VULNERABILITY_ID], 'SQL6-D0-014200' AS [RULE_ID],
       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 OR
                 (SELECT COUNT(*) FROM sys.server_audit_specifications s
                  JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                  JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                  WHERE a.is_state_enabled = 1
                  AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                             ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                             ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                             ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                             ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                             ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                             ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                             ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                             ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                             ,'SERVER_PERMISSION_CHANGE_GROUP'
                                             ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'OPEN'
           ELSE 'Not a finding' END AS [FINDING_STATUS],

	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
            WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1
                 AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'The required audit actions are not included in the server audit specification.'
           ELSE 'No further action required.' END AS [CONFIG_VALUE],

       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured.'
            WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1
                 AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'The required audit actions are not included in the server audit specification.'
           ELSE 'No further action required.' END AS [NOTES]



UNION ALL



SELECT 'V-214000' AS [VULNERABILITY_ID], 'SQL6-D0-013400' AS [RULE_ID],
       CASE
           WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 OR
                (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1
                 AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'OPEN'
           ELSE 'Not a finding' END AS [FINDING_STATUS],

	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
            WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1
                 AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                           ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                           ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                           ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'The required audit actions are not included in the server audit specification.'
           ELSE 'No further action required.' END AS [CONFIG_VALUE],

       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured.'
            WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1
                 AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                           ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                           ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                           ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'The required audit actions are not included in the server audit specification.'
           ELSE 'No further action required.' END AS [NOTES]



UNION ALL



SELECT 'V-214001' AS [VULNERABILITY_ID], 'SQL6-D0-013500' AS [RULE_ID],
       CASE
           WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 OR
                (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1
                 AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                           ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                           ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                           ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'OPEN'
           ELSE 'Not a finding' END AS [FINDING_STATUS],

	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
            WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1
                 AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'The required audit actions are not included in the server audit specification.'
           ELSE 'No further action required.' END AS [CONFIG_VALUE],

       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured.'
            WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1
                 AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                           ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                           ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                           ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                           ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_PERMISSION_CHANGE_GROUP'
                                           ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'The required audit actions are not included in the server audit specification.'
           ELSE 'No further action required.' END AS [NOTES]



UNION ALL



SELECT 'V-214002' AS [VULNERABILITY_ID], 'SQL6-D0-013600' AS [RULE_ID],
       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 OR
                (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1
                 AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'OPEN'
           ELSE 'Not a finding' END AS [FINDING_STATUS],

	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
            WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1
                 AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'The required audit actions are not included in the server audit specification.'
           ELSE 'No further action required.' END AS [CONFIG_VALUE],
       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured.'
            WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1
                 AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_OWNERSHIP_CHANGE_GROUP'
                                            ,'DATABASE_PERMISSION_CHANGE_GROUP'
                                            ,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
                                            ,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_PERMISSION_CHANGE_GROUP'
                                            ,'SERVER_ROLE_MEMBER_CHANGE_GROUP')) < 11 THEN 'The required audit actions are not included in the server audit specification.'
           ELSE 'No further action required.' END AS [NOTES]



UNION ALL



SELECT 'V-214009' AS [VULNERABILITY_ID], 'SQL6-D0-014300' AS [RULE_ID],
       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 OR
                NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications s
                            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP') THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],

	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
            WHEN NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications s
                            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP')
           THEN 'The "SCHEMA_OBJECT_CHANGE_GROUP" is not included in the server audit specification.'
           ELSE 'SQL Server Audit is configured and the "SCHEMA_OBJECT_CHANGE_GROUP" action is included in the server audit specification.'
       END AS [CONFIG_VALUE],

       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured.'
            WHEN NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications s
                            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP')
           THEN 'The "SCHEMA_OBJECT_CHANGE_GROUP" is not included in the server audit specification.'
           ELSE 'No Further Action is required'
       END AS [NOTES]



UNION ALL



SELECT 'V-214003' AS [VULNERABILITY_ID], 'SQL6-D0-013700' AS [RULE_ID],
       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 OR
                NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications s
                            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP') THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],
	   
	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
            WHEN NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications s
                            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP')
           THEN 'The "SCHEMA_OBJECT_CHANGE_GROUP" is not included in the server audit specification.'
           ELSE 'SQL Server Audit is configured and the "SCHEMA_OBJECT_CHANGE_GROUP" action is included in the server audit specification.'
       END AS [CONFIG_VALUE],
       
	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured.'
            WHEN NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications s
                            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP')
           THEN 'The "SCHEMA_OBJECT_CHANGE_GROUP" is not included in the server audit specification.'
           ELSE 'No Further Action is required'
       END AS [NOTES]



UNION ALL



SELECT 'V-214004' AS [VULNERABILITY_ID], 'SQL6-D0-013800' AS [RULE_ID],
       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 OR
                NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications s
                            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP') THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],
	   
	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
            WHEN NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications s
                            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP')
           THEN 'The "SCHEMA_OBJECT_CHANGE_GROUP" is not included in the server audit specification.'
           ELSE 'SQL Server Audit is configured and the "SCHEMA_OBJECT_CHANGE_GROUP" action is included in the server audit specification.'
       END AS [CONFIG_VALUE],
       
	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured.'
            WHEN NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications s
                            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP')
           THEN 'The "SCHEMA_OBJECT_CHANGE_GROUP" is not included in the server audit specification.'
           ELSE 'No Further Action is required'
       END AS [NOTES]



UNION ALL



SELECT 'V-214005' AS [VULNERABILITY_ID], 'SQL6-D0-013900' AS [RULE_ID],
       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],

	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
			WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
            OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
            OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))	
           THEN 'Check system documentation for audit requirements when data classifications are modified.'
           ELSE 'No further action required.' END AS [CONFIG_VALUE],

       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'Review system documentation to determine if SQL Server is required to audit when data classifications are modified.'
           ELSE 'No further action required.' END AS [NOTES]



UNION ALL



SELECT 'V-214006' AS [VULNERABILITY_ID], 'SQL6-D0-014000' AS [RULE_ID],
       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],

	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
			WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
            OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
            OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))	
           THEN 'Check system documentation for audit requirements when data classifications are unsuccessfully modified.'
           ELSE 'No further action required.' END AS [CONFIG_VALUE],

       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'Review system documentation to determine if SQL Server is required to audit when data classifications are unsuccessfully modified.'
           ELSE 'No further action required.' END AS [NOTES]



UNION ALL



SELECT 'V-213948' AS [VULNERABILITY_ID], 'SQL6-D0-006300' AS [RULE_ID],
       CASE WHEN EXISTS (SELECT login.name, perm.permission_name, perm.state_desc
                        FROM sys.server_permissions perm
                        JOIN sys.server_principals login
                        ON perm.grantee_principal_id = login.principal_id
                        WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT')
                        and login.name not like '##MS_%') THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],

		CASE WHEN EXISTS (SELECT login.name, perm.permission_name, perm.state_desc
                        FROM sys.server_permissions perm
                        JOIN sys.server_principals login
                        ON perm.grantee_principal_id = login.principal_id
                        WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT')
                        and login.name not like '##MS_%')
           THEN 'Check the server documentation for a list of approved users with access to SQL Server Audits.' 
           ELSE 'No unauthorized accounts found with ALTER ANY SERVER AUDIT or CONTROL SERVER permissions.'
       END AS [CONFIG_VALUE],

       CASE WHEN EXISTS (SELECT login.name, perm.permission_name, perm.state_desc
                        FROM sys.server_permissions perm
                        JOIN sys.server_principals login
                        ON perm.grantee_principal_id = login.principal_id
                        WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT')
                        and login.name not like '##MS_%')
           THEN 'Unauthorized accounts have been granted ALTER ANY SERVER AUDIT or CONTROL SERVER permissions.' 
           ELSE 'No further action required.'
       END AS [NOTES]



UNION ALL



SELECT 'V-213949' AS [VULNERABILITY_ID], 'SQL6-D0-006400' AS [RULE_ID],
       CASE WHEN EXISTS (SELECT login.name, perm.permission_name, perm.state_desc
                        FROM sys.server_permissions perm
                        JOIN sys.server_principals login
                        ON perm.grantee_principal_id = login.principal_id
                        WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT')
                        and login.name not like '##MS_%') THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],

		CASE WHEN EXISTS (SELECT login.name, perm.permission_name, perm.state_desc
                        FROM sys.server_permissions perm
                        JOIN sys.server_principals login
                        ON perm.grantee_principal_id = login.principal_id
                        WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT')
                        and login.name not like '##MS_%')
           THEN 'Check the server documentation for a list of approved users with access to SQL Server Audits.' 
           ELSE 'No unauthorized accounts found with ALTER ANY SERVER AUDIT or CONTROL SERVER permissions.'
       END AS [CONFIG_VALUE],

       CASE WHEN EXISTS (SELECT login.name, perm.permission_name, perm.state_desc
                        FROM sys.server_permissions perm
                        JOIN sys.server_principals login
                        ON perm.grantee_principal_id = login.principal_id
                        WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT')
                        and login.name not like '##MS_%')
           THEN 'Unauthorized accounts have been granted ALTER ANY SERVER AUDIT or CONTROL SERVER permissions.' 
           ELSE 'No further action required.'
       END AS [NOTES]



UNION ALL



SELECT 'V-213940' AS [VULNERABILITY_ID], 'SQL6-D0-004700' AS [RULE_ID],
       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED') = 0 THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],
       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED') = 0 THEN 'No audits are configured and enabled.' ELSE 'Audits are configured and enabled.' END AS [CONFIG_VALUE],
       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED') = 0 THEN 'No audits are configured and enabled.' ELSE 'Audits are configured and enabled.' END AS [NOTES]



UNION ALL



SELECT 'V-213942' AS [VULNERABILITY_ID], 'SQL6-D0-005600' AS [RULE_ID],
       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED') = 0 THEN 'OPEN'
			WHEN EXISTS (SELECT * FROM sys.server_audits WHERE on_failure_desc <> 'SHUTDOWN SERVER INSTANCE') THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],
	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED') = 0 THEN 'The SQL Server Audit is not configured and started.'
			WHEN EXISTS (SELECT * FROM sys.server_audits WHERE on_failure_desc <> 'SHUTDOWN SERVER INSTANCE') THEN 'Review if system documentation indicates that availability takes precedence over audit trail completeness' ELSE 'SERVER SHUTDOWN INSTANCE is configured' END AS [CONFIG_VALUE],
	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED') = 0 THEN 'Review if system documentation indicates that availability takes precedence over audit trail completeness'
			WHEN EXISTS (SELECT * FROM sys.server_audits WHERE on_failure_desc <> 'SHUTDOWN SERVER INSTANCE') THEN 'Review if system documentation' ELSE 'No further action required' END AS [NOTES]



UNION ALL



SELECT 'V-213943' AS [VULNERABILITY_ID], 'SQL6-D0-005700' AS [RULE_ID],
	CASE WHEN NOT EXISTS (SELECT * FROM sys.server_audits WHERE is_state_enabled = 1) THEN 'OPEN'
         WHEN EXISTS (SELECT * FROM sys.server_audits WHERE type_desc IN ('APPLICATION LOG', 'SECURITY LOG')) THEN 'Not a finding'
         WHEN EXISTS (SELECT * FROM sys.server_audits a LEFT JOIN sys.server_file_audits f ON a.audit_id = f.audit_id WHERE a.is_state_enabled = 1 AND a.type_desc = 'FILE' AND f.max_rollover_files > 0) THEN 'Not a finding'
         ELSE 'OPEN' END AS [FINDING_STATUS],

	CASE WHEN NOT EXISTS (SELECT * FROM sys.server_audits WHERE is_state_enabled = 1) THEN 'The SQL Server Audit is not configured and started.'
         WHEN EXISTS (SELECT * FROM sys.server_audits WHERE type_desc IN ('APPLICATION LOG', 'SECURITY LOG')) THEN 'APPLICATION/SECURITY LOG'
         WHEN EXISTS (SELECT * FROM sys.server_audits a LEFT JOIN sys.server_file_audits f ON a.audit_id = f.audit_id WHERE a.is_state_enabled = 1 AND a.type_desc = 'FILE' AND f.max_rollover_files > 0) THEN 'Storage Type = FILE / Max Rollover > 0' 
		 ELSE 'Review  if system documentation indicates that availability does not take precedence over audit trail completeness.' END AS [CONFIG_VALUE],

	CASE WHEN NOT EXISTS (SELECT * FROM sys.server_audits WHERE is_state_enabled = 1) THEN 'Audits not configured.'
         WHEN EXISTS (SELECT * FROM sys.server_audits WHERE type_desc IN ('APPLICATION LOG', 'SECURITY LOG')) THEN 'Application or Security Logs are configured'
         WHEN EXISTS (SELECT * FROM sys.server_audits a LEFT JOIN sys.server_file_audits f ON a.audit_id = f.audit_id WHERE a.is_state_enabled = 1 AND a.type_desc = 'FILE' AND f.max_rollover_files > 0) THEN 'Storage type is "file" and max rollover files is greater than 50' 
		 ELSE 'Review if system documentation indicates that availability does not take precedence over audit trail completeness.' END AS [NOTES]

UNION ALL

SELECT 'V-213947' AS [VULNERABILITY_ID], 'SQL6-D0-006200' AS [RULE_ID],
       CASE WHEN EXISTS (SELECT 1 FROM sys.server_permissions perm JOIN sys.server_principals login ON perm.grantee_principal_id = login.principal_id WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT','ALTER TRACE') AND login.name not like '##MS_%' AND perm.state_desc = 'GRANT') THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],

       CASE WHEN EXISTS (SELECT 1 FROM sys.server_permissions perm JOIN sys.server_principals login ON perm.grantee_principal_id = login.principal_id WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT','ALTER TRACE') AND login.name not like '##MS_%' AND perm.state_desc = 'GRANT')
           THEN 'Check the server documentation for a list of approved users with access to SQL Server Audits.' 
           ELSE 'No unauthorized accounts found with the required permissions.'
       END AS [CONFIG_VALUE],

       CASE WHEN EXISTS (SELECT 1 FROM sys.server_permissions perm JOIN sys.server_principals login ON perm.grantee_principal_id = login.principal_id WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT','ALTER TRACE') AND login.name not like '##MS_%' AND perm.state_desc = 'GRANT')
           THEN 'Unauthorized accounts have been granted the required permissions.' 
           ELSE 'No further action required.'
       END AS [NOTES]



UNION ALL



SELECT 'V-214019' AS [VULNERABILITY_ID], 'SQL6-D0-015300' AS [RULE_ID],
       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],

	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
			WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
            OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
            OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))	
           THEN 'Check system documentation to determine if SQL Server is required to audit when successful accesses to objects occur.'
           ELSE 'No further action required.' END AS [CONFIG_VALUE],

       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'Review system documentation to determine if SQL Server is required to audit when successful accesses to objects occur.'
           ELSE 'No further action required.' END AS [NOTES]



UNION ALL



SELECT 'V-214018' AS [VULNERABILITY_ID], 'SQL6-D0-015200' AS [RULE_ID],
       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'OPEN' 
            WHEN EXISTS (SELECT * FROM sys.server_audit_specifications s
                          JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                          JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                          WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP') THEN 'Not a finding' 
            ELSE CASE WHEN (SELECT value FROM sys.configurations WHERE name = 'audit login failed' AND value = 1) = 0 AND (SELECT value FROM sys.configurations WHERE name = 'audit login success' AND value = 1) = 0 THEN 'OPEN'
                    ELSE 'Not a finding' END END AS [FINDING_STATUS],

       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
            WHEN EXISTS (SELECT * FROM sys.server_audit_specifications s
                          JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                          JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                          WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP') THEN 'The "SUCCESSFUL_LOGIN_GROUP" is included in the server audit specification.' 
            ELSE CASE WHEN (SELECT value FROM sys.configurations WHERE name = 'audit login failed' AND value = 1) = 0  AND (SELECT value FROM sys.configurations WHERE name = 'audit login success' AND value = 1) = 0 THEN 'Login auditing is not set to audit both failed and successful logins.'
                    ELSE 'Auditing both failed and successful logins is enabled.' END END AS [CONFIG_VALUE],

       CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured'
            WHEN EXISTS (SELECT * FROM sys.server_audit_specifications s
                          JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                          JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                          WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP') THEN 'No further action required.' 
            ELSE CASE WHEN (SELECT value FROM sys.configurations WHERE name = 'audit login failed' AND value = 1) = 0 AND (SELECT value FROM sys.configurations WHERE name = 'audit login success' AND value = 1) = 0 THEN 'Configure login auditing to audit both failed and successful logins.'
                    ELSE 'No further action required.' END END AS [NOTES]



UNION ALL



SELECT 'V-214013' AS [VULNERABILITY_ID], 'SQL6-D0-014700' AS [RULE_ID],
       CASE
           WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'OPEN'
           WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP') > 0 THEN 'Not a finding'
           ELSE 'Finding' END AS [FINDING_STATUS],
       CASE
           WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
           WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP') > 0 THEN 'SUCCESSFUL_LOGIN_GROUP is included in the server audit specification and "Both failed and successful logins" is enabled.'
           ELSE 'SUCCESSFUL_LOGIN_GROUP is not included in the server audit specification or "Both failed and successful logins" is not enabled.' END AS [CONFIG_VALUE],
       CASE
           WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured'
           WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
                 JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                 JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                 WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP') = 0 AND
                (SELECT CONVERT(INT, value_in_use) FROM sys.configurations WHERE name = 'audit login failure event') = 0 THEN
                    'SUCCESSFUL_LOGIN_GROUP is not included in the server audit specification and "Both failed and successful logins" is not enabled.'
           ELSE 'No further action required.' END AS [NOTES]



UNION ALL



SELECT 'V-214012' AS [VULNERABILITY_ID], 'SQL6-D0-014600' AS [RULE_ID],
       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],

	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
			WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
            OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
            OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))	
           THEN 'Check system documentation to determine if SQL Server is required to audit when data classifications are unsuccessfully deleted.'
           ELSE 'No further action required.' END AS [CONFIG_VALUE],

       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'Review system documentation to determine if SQL Server is required to audit when data classifications are unsuccessfully deleted.'
           ELSE 'No further action required.' END AS [NOTES]



UNION ALL



SELECT 'V-214011' AS [VULNERABILITY_ID], 'SQL6-D0-014500' AS [RULE_ID],
       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],

	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
			WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
            OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
            OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))	
           THEN 'Check system documentation to determine if SQL Server is required to audit when data classifications are deleted.'
           ELSE 'No further action required.' END AS [CONFIG_VALUE],

       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'Review system documentation to determine if SQL Server is required to audit when data classifications are deleted.'
           ELSE 'No further action required.' END AS [NOTES]

UNION ALL

SELECT 'V-214010' AS [VULNERABILITY_ID], 'SQL6-D0-014400' AS [RULE_ID],
       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'OPEN' ELSE 'Not a finding' END AS [FINDING_STATUS],

	   CASE WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
			WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
            OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
            OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))	
           THEN 'SCHEMA_OBJECT_ACCESS_GROUP is not configured.'
           ELSE 'No further action required.' END AS [CONFIG_VALUE],

       CASE WHEN NOT EXISTS (SELECT * FROM sys.dm_server_audit_status)
                OR NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)) 
                OR NOT EXISTS (SELECT 1 FROM sys.server_audit_specification_details WHERE audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND server_specification_id IN (SELECT server_specification_id FROM sys.server_audit_specifications WHERE audit_guid = (SELECT TOP 1 audit_guid FROM sys.server_audits WHERE is_state_enabled = 1)))
           THEN 'Create the SCHEMA_OBJECT_ACCESS_GROUP within the SQL Instance'
           ELSE 'No further action required.' END AS [NOTES]



UNION ALL



SELECT 'V-214017' AS [VULNERABILITY_ID], 'SQL6-D0-015100' AS [RULE_ID],
    CASE 
        WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'OPEN'
        WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
                'AUDIT_CHANGE_GROUP',
                'BACKUP_RESTORE_GROUP',
                'DATABASE_CHANGE_GROUP',
                'DATABASE_OBJECT_CHANGE_GROUP',
                'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                'DATABASE_OPERATION_GROUP',
                'DATABASE_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_PERMISSION_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
                'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                'DBCC_GROUP',
                'LOGIN_CHANGE_PASSWORD_GROUP',
                'LOGOUT_GROUP',
                'SCHEMA_OBJECT_CHANGE_GROUP',
                'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OBJECT_CHANGE_GROUP',
                'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OPERATION_GROUP',
                'SERVER_PERMISSION_CHANGE_GROUP',
                'SERVER_PRINCIPAL_CHANGE_GROUP',
                'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
                'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                'SERVER_STATE_CHANGE_GROUP',
                'TRACE_CHANGE_GROUP',
                'USER_CHANGE_PASSWORD_GROUP'
            )
        ) = 27 THEN 'Not a finding'
        ELSE 'OPEN'
    END AS [FINDING_STATUS],
    CASE 
        WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
        WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
                'AUDIT_CHANGE_GROUP',
                'BACKUP_RESTORE_GROUP',
                'DATABASE_CHANGE_GROUP',
                'DATABASE_OBJECT_CHANGE_GROUP',
                'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                'DATABASE_OPERATION_GROUP',
                'DATABASE_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_PERMISSION_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
                'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                'DBCC_GROUP',
                'LOGIN_CHANGE_PASSWORD_GROUP',
                'LOGOUT_GROUP',
                'SCHEMA_OBJECT_CHANGE_GROUP',
                'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OBJECT_CHANGE_GROUP',
                'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OPERATION_GROUP',
                'SERVER_PERMISSION_CHANGE_GROUP',
                'SERVER_PRINCIPAL_CHANGE_GROUP',
                'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
                'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                'SERVER_STATE_CHANGE_GROUP',
                'TRACE_CHANGE_GROUP',
                'USER_CHANGE_PASSWORD_GROUP'
            )
        ) = 27 THEN 'All the required audit groups are included in the server audit specification.'
		ELSE 'One or more of the required audit groups are not included in the server audit specification.' END AS [CONFIG_VALUE],
    CASE 
        WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured.'
        WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
                'AUDIT_CHANGE_GROUP',
                'BACKUP_RESTORE_GROUP',
                'DATABASE_CHANGE_GROUP',
                'DATABASE_OBJECT_CHANGE_GROUP',
                'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                'DATABASE_OPERATION_GROUP',
                'DATABASE_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_PERMISSION_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
                'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                'DBCC_GROUP',
                'LOGIN_CHANGE_PASSWORD_GROUP',
                'LOGOUT_GROUP',
                'SCHEMA_OBJECT_CHANGE_GROUP',
                'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OBJECT_CHANGE_GROUP',
                'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OPERATION_GROUP',
                'SERVER_PERMISSION_CHANGE_GROUP',
                'SERVER_PRINCIPAL_CHANGE_GROUP',
                'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
                'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                'SERVER_STATE_CHANGE_GROUP',
                'TRACE_CHANGE_GROUP',
                'USER_CHANGE_PASSWORD_GROUP'
            )
        ) = 27 THEN 'All the required audit groups are included in the server audit specification.'
		ELSE 'One or more of the required audit groups are not included in the server audit specification.' END AS [NOTES]



UNION ALL



SELECT 'V-214016' AS [VULNERABILITY_ID], 'SQL6-D0-015000' AS [RULE_ID],
    CASE 
        WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'OPEN'
        WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
                'AUDIT_CHANGE_GROUP',
                'BACKUP_RESTORE_GROUP',
                'DATABASE_CHANGE_GROUP',
                'DATABASE_OBJECT_CHANGE_GROUP',
                'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                'DATABASE_OPERATION_GROUP',
                'DATABASE_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_PERMISSION_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
                'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                'DBCC_GROUP',
                'LOGIN_CHANGE_PASSWORD_GROUP',
                'LOGOUT_GROUP',
                'SCHEMA_OBJECT_CHANGE_GROUP',
                'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OBJECT_CHANGE_GROUP',
                'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OPERATION_GROUP',
                'SERVER_PERMISSION_CHANGE_GROUP',
                'SERVER_PRINCIPAL_CHANGE_GROUP',
                'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
                'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                'SERVER_STATE_CHANGE_GROUP',
                'TRACE_CHANGE_GROUP',
                'USER_CHANGE_PASSWORD_GROUP'
            )
        ) = 27 THEN 'Not a finding'
        ELSE 'OPEN'
    END AS [FINDING_STATUS],
    CASE 
        WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
        WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
                'AUDIT_CHANGE_GROUP',
                'BACKUP_RESTORE_GROUP',
                'DATABASE_CHANGE_GROUP',
                'DATABASE_OBJECT_CHANGE_GROUP',
                'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                'DATABASE_OPERATION_GROUP',
                'DATABASE_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_PERMISSION_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
                'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                'DBCC_GROUP',
                'LOGIN_CHANGE_PASSWORD_GROUP',
                'LOGOUT_GROUP',
                'SCHEMA_OBJECT_CHANGE_GROUP',
                'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OBJECT_CHANGE_GROUP',
                'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OPERATION_GROUP',
                'SERVER_PERMISSION_CHANGE_GROUP',
                'SERVER_PRINCIPAL_CHANGE_GROUP',
                'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
                'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                'SERVER_STATE_CHANGE_GROUP',
                'TRACE_CHANGE_GROUP',
                'USER_CHANGE_PASSWORD_GROUP'
            )
        ) = 27 THEN 'All the required audit groups are included in the server audit specification.'
		ELSE 'One or more of the required audit groups are not included in the server audit specification.' END AS [CONFIG_VALUE],
    CASE 
        WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured.'
        WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
                'AUDIT_CHANGE_GROUP',
                'BACKUP_RESTORE_GROUP',
                'DATABASE_CHANGE_GROUP',
                'DATABASE_OBJECT_CHANGE_GROUP',
                'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                'DATABASE_OPERATION_GROUP',
                'DATABASE_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_PERMISSION_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
                'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                'DBCC_GROUP',
                'LOGIN_CHANGE_PASSWORD_GROUP',
                'LOGOUT_GROUP',
                'SCHEMA_OBJECT_CHANGE_GROUP',
                'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OBJECT_CHANGE_GROUP',
                'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OPERATION_GROUP',
                'SERVER_PERMISSION_CHANGE_GROUP',
                'SERVER_PRINCIPAL_CHANGE_GROUP',
                'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
                'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                'SERVER_STATE_CHANGE_GROUP',
                'TRACE_CHANGE_GROUP',
                'USER_CHANGE_PASSWORD_GROUP'
            )
        ) = 27 THEN 'All the required audit groups are included in the server audit specification.'
		ELSE 'One or more of the required audit groups are not included in the server audit specification.' END AS [NOTES]



UNION ALL



SELECT 'V-214015' AS [VULNERABILITY_ID], 'SQL6-D0-014900' AS [RULE_ID],
    CASE 
        WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'OPEN'
        WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
                'AUDIT_CHANGE_GROUP',
                'BACKUP_RESTORE_GROUP',
                'DATABASE_CHANGE_GROUP',
                'DATABASE_OBJECT_CHANGE_GROUP',
                'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                'DATABASE_OPERATION_GROUP',
                'DATABASE_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_PERMISSION_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
                'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                'DBCC_GROUP',
                'LOGIN_CHANGE_PASSWORD_GROUP',
                'LOGOUT_GROUP',
                'SCHEMA_OBJECT_CHANGE_GROUP',
                'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OBJECT_CHANGE_GROUP',
                'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OPERATION_GROUP',
                'SERVER_PERMISSION_CHANGE_GROUP',
                'SERVER_PRINCIPAL_CHANGE_GROUP',
                'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
                'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                'SERVER_STATE_CHANGE_GROUP',
                'TRACE_CHANGE_GROUP',
                'USER_CHANGE_PASSWORD_GROUP'
            )
        ) = 27 THEN 'Not a finding'
        ELSE 'OPEN'
    END AS [FINDING_STATUS],
    CASE 
        WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'The SQL Server Audit is not configured and started.'
        WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
                'AUDIT_CHANGE_GROUP',
                'BACKUP_RESTORE_GROUP',
                'DATABASE_CHANGE_GROUP',
                'DATABASE_OBJECT_CHANGE_GROUP',
                'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                'DATABASE_OPERATION_GROUP',
                'DATABASE_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_PERMISSION_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
                'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                'DBCC_GROUP',
                'LOGIN_CHANGE_PASSWORD_GROUP',
                'LOGOUT_GROUP',
                'SCHEMA_OBJECT_CHANGE_GROUP',
                'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OBJECT_CHANGE_GROUP',
                'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OPERATION_GROUP',
                'SERVER_PERMISSION_CHANGE_GROUP',
                'SERVER_PRINCIPAL_CHANGE_GROUP',
                'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
                'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                'SERVER_STATE_CHANGE_GROUP',
                'TRACE_CHANGE_GROUP',
                'USER_CHANGE_PASSWORD_GROUP'
            )
        ) = 27 THEN 'All the required audit groups are included in the server audit specification.'
		ELSE 'One or more of the required audit groups are not included in the server audit specification.' END AS [CONFIG_VALUE],
    CASE 
        WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status) = 0 THEN 'Audits not configured.'
        WHEN (SELECT COUNT(*) FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
                'AUDIT_CHANGE_GROUP',
                'BACKUP_RESTORE_GROUP',
                'DATABASE_CHANGE_GROUP',
                'DATABASE_OBJECT_CHANGE_GROUP',
                'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                'DATABASE_OPERATION_GROUP',
                'DATABASE_OWNERSHIP_CHANGE_GROUP',
                'DATABASE_PERMISSION_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_CHANGE_GROUP',
                'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
                'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                'DBCC_GROUP',
                'LOGIN_CHANGE_PASSWORD_GROUP',
                'LOGOUT_GROUP',
                'SCHEMA_OBJECT_CHANGE_GROUP',
                'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OBJECT_CHANGE_GROUP',
                'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                'SERVER_OPERATION_GROUP',
                'SERVER_PERMISSION_CHANGE_GROUP',
                'SERVER_PRINCIPAL_CHANGE_GROUP',
                'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
                'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                'SERVER_STATE_CHANGE_GROUP',
                'TRACE_CHANGE_GROUP',
                'USER_CHANGE_PASSWORD_GROUP'
            )
        ) = 27 THEN 'All the required audit groups are included in the server audit specification.'
		ELSE 'One or more of the required audit groups are not included in the server audit specification.' END AS [NOTES]




ORDER BY vulnerability_id
