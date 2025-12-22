CREATE TABLE Targets(
    id INT PRIMARY KEY,
    ip_addr VARCHAR(15) UNIQUE NOT NULL,
    port INT NOT NULL,
    results TEXT,
    responsive BOOL
);

CREATE TABLE ToScan(
    id INT PRIMARY KEY,
    ip_addr VARCHAR(15) UNIQUE NOT NULL,
    port INT NOT NULL
);