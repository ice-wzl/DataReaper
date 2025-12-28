CREATE TABLE Targets(
    id INT PRIMARY KEY,
    ip_addr VARCHAR(15) UNIQUE NOT NULL,
    port INT NOT NULL,
    scan_date DATETIME NOT NULL,
    results TEXT
);

CREATE TABLE ToScan(
    id INT PRIMARY KEY,
    ip_addr VARCHAR(15) UNIQUE NOT NULL,
    port INT NOT NULL
);

CREATE TABLE DownloadTargets(
    id INT PRIMARY KEY,
    ip_addr VARCHAR(15),
    port INT NOT NULL
);