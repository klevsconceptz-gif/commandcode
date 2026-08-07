INSERT OR IGNORE INTO payment_settings (method, display_name, is_active, logo, details) VALUES
('bitcoin','Bitcoin (BTC)',1,'/images/bitcoin.webp','[{"label":"Wallet Address","value":"bc1q04k3fuas4eratzmv9padu9zjf7dwh4xv0s23k6","copyable":true}]'),
('cashapp','Cash App',1,'/images/cashapp.webp','[{"label":"$Cashtag","value":"$QuantumSpaceX","copyable":true}]'),
('paypal','PayPal',1,'/images/paypal.png','[{"label":"Email","value":"paypal@quantumspacex.online","copyable":true}]'),
('zelle','Zelle',1,'/images/zelle.png','[{"label":"Email","value":"zelle@quantumspacex.online","copyable":true}]'),
('wire','Wire Transfer',1,'/images/wire-transfer.webp','[{"label":"Bank","value":"Chase Bank"},{"label":"Account","value":"123456789"},{"label":"Routing","value":"021000021","copyable":true}]'),
('western-union','Western Union',1,'/images/western-union.jpg','[{"label":"Name","value":"Quantum Space X LLC"},{"label":"City","value":"New York"},{"label":"Country","value":"United States"}]');
INSERT OR IGNORE INTO admin_settings (key, value) VALUES
('min_deposit','100'),('max_deposit','1000000'),('site_name','Quantum Space X'),('support_email','Elonmusk2207@gmail.com'),('support_phone','+1 (262) 526-7600'),('telegram','@quantumspacex1');
