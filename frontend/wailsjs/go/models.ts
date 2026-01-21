export namespace analysis {
	
	export class Host {
	    ip: string;
	    mac: string;
	    hostname: string;
	    os: string;
	    open_ports: number[];
	    packets_sent: number;
	    packets_received: number;
	    bytes_sent: number;
	    bytes_recv: number;
	    ttl: number;
	    firstSeen: string;
	    lastSeen: string;
	    country: string;
	    countryISO: string;
	    city: string;
	    latitude: number;
	    longitude: number;
	    asn: number;
	    organization: string;
	
	    static createFrom(source: any = {}) {
	        return new Host(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.hostname = source["hostname"];
	        this.os = source["os"];
	        this.open_ports = source["open_ports"];
	        this.packets_sent = source["packets_sent"];
	        this.packets_received = source["packets_received"];
	        this.bytes_sent = source["bytes_sent"];
	        this.bytes_recv = source["bytes_recv"];
	        this.ttl = source["ttl"];
	        this.firstSeen = source["firstSeen"];
	        this.lastSeen = source["lastSeen"];
	        this.country = source["country"];
	        this.countryISO = source["countryISO"];
	        this.city = source["city"];
	        this.latitude = source["latitude"];
	        this.longitude = source["longitude"];
	        this.asn = source["asn"];
	        this.organization = source["organization"];
	    }
	}
	export class Session {
	    key: string;
	    src_ip: string;
	    src_port: number;
	    dst_ip: string;
	    dst_port: number;
	    protocol: string;
	    // Go type: time
	    start_time: any;
	    // Go type: time
	    end_time: any;
	    duration: string;
	    packet_count: number;
	    byte_count: number;
	    payload_size: number;
	    ja3: string;
	    ja3_digest: string;
	    decrypted_content: string;
	
	    static createFrom(source: any = {}) {
	        return new Session(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.src_ip = source["src_ip"];
	        this.src_port = source["src_port"];
	        this.dst_ip = source["dst_ip"];
	        this.dst_port = source["dst_port"];
	        this.protocol = source["protocol"];
	        this.start_time = this.convertValues(source["start_time"], null);
	        this.end_time = this.convertValues(source["end_time"], null);
	        this.duration = source["duration"];
	        this.packet_count = source["packet_count"];
	        this.byte_count = source["byte_count"];
	        this.payload_size = source["payload_size"];
	        this.ja3 = source["ja3"];
	        this.ja3_digest = source["ja3_digest"];
	        this.decrypted_content = source["decrypted_content"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TimeBucket {
	    timestamp: string;
	    bytes: number;
	    packets: number;
	
	    static createFrom(source: any = {}) {
	        return new TimeBucket(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.bytes = source["bytes"];
	        this.packets = source["packets"];
	    }
	}

}

export namespace anomalies {
	
	export class Anomaly {
	    frame_number: number;
	    timestamp: string;
	    type: string;
	    severity: string;
	    description: string;
	    source_ip: string;
	    source_port: number;
	    dest_ip: string;
	    dest_port: number;
	    protocol: string;
	    details: string;
	
	    static createFrom(source: any = {}) {
	        return new Anomaly(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.frame_number = source["frame_number"];
	        this.timestamp = source["timestamp"];
	        this.type = source["type"];
	        this.severity = source["severity"];
	        this.description = source["description"];
	        this.source_ip = source["source_ip"];
	        this.source_port = source["source_port"];
	        this.dest_ip = source["dest_ip"];
	        this.dest_port = source["dest_port"];
	        this.protocol = source["protocol"];
	        this.details = source["details"];
	    }
	}

}

export namespace assembly {
	
	export class FileDetail {
	    filename: string;
	    size: number;
	    path: string;
	    extension: string;
	    md5: string;
	    sha256: string;
	    source_ip: string;
	    dest_ip: string;
	    source_port: number;
	    dest_port: number;
	
	    static createFrom(source: any = {}) {
	        return new FileDetail(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.filename = source["filename"];
	        this.size = source["size"];
	        this.path = source["path"];
	        this.extension = source["extension"];
	        this.md5 = source["md5"];
	        this.sha256 = source["sha256"];
	        this.source_ip = source["source_ip"];
	        this.dest_ip = source["dest_ip"];
	        this.source_port = source["source_port"];
	        this.dest_port = source["dest_port"];
	    }
	}

}

export namespace certificates {
	
	export class Certificate {
	    subject: string;
	    issuer: string;
	    serial_number: string;
	    not_before: string;
	    not_after: string;
	    is_expired: boolean;
	    days_until_expiry: number;
	    is_self_signed: boolean;
	    sha256: string;
	    server_ip: string;
	    server_port: number;
	    client_ip: string;
	    timestamp: string;
	    signature_algorithm: string;
	
	    static createFrom(source: any = {}) {
	        return new Certificate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.serial_number = source["serial_number"];
	        this.not_before = source["not_before"];
	        this.not_after = source["not_after"];
	        this.is_expired = source["is_expired"];
	        this.days_until_expiry = source["days_until_expiry"];
	        this.is_self_signed = source["is_self_signed"];
	        this.sha256 = source["sha256"];
	        this.server_ip = source["server_ip"];
	        this.server_port = source["server_port"];
	        this.client_ip = source["client_ip"];
	        this.timestamp = source["timestamp"];
	        this.signature_algorithm = source["signature_algorithm"];
	    }
	}

}

export namespace credentials {
	
	export class Credential {
	    protocol: string;
	    client_ip: string;
	    client_port: string;
	    server_ip: string;
	    server_port: string;
	    username: string;
	    password: string;
	    captured: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Credential(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.protocol = source["protocol"];
	        this.client_ip = source["client_ip"];
	        this.client_port = source["client_port"];
	        this.server_ip = source["server_ip"];
	        this.server_port = source["server_port"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.captured = source["captured"];
	    }
	}

}

export namespace dns {
	
	export class Record {
	    timestamp: string;
	    transaction_id: number;
	    query: string;
	    type: string;
	    answers: string;
	    response_code: string;
	    is_response: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Record(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.transaction_id = source["transaction_id"];
	        this.query = source["query"];
	        this.type = source["type"];
	        this.answers = source["answers"];
	        this.response_code = source["response_code"];
	        this.is_response = source["is_response"];
	    }
	}

}

export namespace http {
	
	export class Transaction {
	    timestamp: string;
	    frame_num: number;
	    src_ip: string;
	    src_port: number;
	    dst_ip: string;
	    dst_port: number;
	    method: string;
	    url: string;
	    host: string;
	    user_agent: string;
	    referer: string;
	    cookie: string;
	
	    static createFrom(source: any = {}) {
	        return new Transaction(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.frame_num = source["frame_num"];
	        this.src_ip = source["src_ip"];
	        this.src_port = source["src_port"];
	        this.dst_ip = source["dst_ip"];
	        this.dst_port = source["dst_port"];
	        this.method = source["method"];
	        this.url = source["url"];
	        this.host = source["host"];
	        this.user_agent = source["user_agent"];
	        this.referer = source["referer"];
	        this.cookie = source["cookie"];
	    }
	}

}

export namespace keywords {
	
	export class Match {
	    keyword: string;
	    context: string;
	    frame_num: number;
	    timestamp: string;
	
	    static createFrom(source: any = {}) {
	        return new Match(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.keyword = source["keyword"];
	        this.context = source["context"];
	        this.frame_num = source["frame_num"];
	        this.timestamp = source["timestamp"];
	    }
	}

}

export namespace main {
	
	export class ImageInfo {
	    filename: string;
	    data: string;
	    source_ip: string;
	    source_port: number;
	    dest_port: number;
	
	    static createFrom(source: any = {}) {
	        return new ImageInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.filename = source["filename"];
	        this.data = source["data"];
	        this.source_ip = source["source_ip"];
	        this.source_port = source["source_port"];
	        this.dest_port = source["dest_port"];
	    }
	}
	export class PcapMetadata {
	    filename: string;
	    size: number;
	    md5: string;
	    first_packet_time: string;
	    last_packet_time: string;
	    duration: string;
	    total_packets: number;
	
	    static createFrom(source: any = {}) {
	        return new PcapMetadata(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.filename = source["filename"];
	        this.size = source["size"];
	        this.md5 = source["md5"];
	        this.first_packet_time = source["first_packet_time"];
	        this.last_packet_time = source["last_packet_time"];
	        this.duration = source["duration"];
	        this.total_packets = source["total_packets"];
	    }
	}
	export class PcapResult {
	    message: string;
	    files: assembly.FileDetail[];
	    hosts: analysis.Host[];
	    credentials: credentials.Credential[];
	    keyword_matches: keywords.Match[];
	    dns_records: dns.Record[];
	    images: ImageInfo[];
	    metadata: PcapMetadata;
	    timeline: analysis.TimeBucket[];
	    protocol_stats: Record<string, number>;
	    service_stats: Record<number, number>;
	    sessions: analysis.Session[];
	    parameters: parameters.Parameter[];
	    messages: messages.Message[];
	    anomalies: anomalies.Anomaly[];
	    certificates: certificates.Certificate[];
	    http_transactions: http.Transaction[];
	    voip_calls: voip.Call[];
	
	    static createFrom(source: any = {}) {
	        return new PcapResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.message = source["message"];
	        this.files = this.convertValues(source["files"], assembly.FileDetail);
	        this.hosts = this.convertValues(source["hosts"], analysis.Host);
	        this.credentials = this.convertValues(source["credentials"], credentials.Credential);
	        this.keyword_matches = this.convertValues(source["keyword_matches"], keywords.Match);
	        this.dns_records = this.convertValues(source["dns_records"], dns.Record);
	        this.images = this.convertValues(source["images"], ImageInfo);
	        this.metadata = this.convertValues(source["metadata"], PcapMetadata);
	        this.timeline = this.convertValues(source["timeline"], analysis.TimeBucket);
	        this.protocol_stats = source["protocol_stats"];
	        this.service_stats = source["service_stats"];
	        this.sessions = this.convertValues(source["sessions"], analysis.Session);
	        this.parameters = this.convertValues(source["parameters"], parameters.Parameter);
	        this.messages = this.convertValues(source["messages"], messages.Message);
	        this.anomalies = this.convertValues(source["anomalies"], anomalies.Anomaly);
	        this.certificates = this.convertValues(source["certificates"], certificates.Certificate);
	        this.http_transactions = this.convertValues(source["http_transactions"], http.Transaction);
	        this.voip_calls = this.convertValues(source["voip_calls"], voip.Call);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class StreamData {
	    inbound: string;
	    outbound: string;
	
	    static createFrom(source: any = {}) {
	        return new StreamData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.inbound = source["inbound"];
	        this.outbound = source["outbound"];
	    }
	}

}

export namespace messages {
	
	export class Attachment {
	    filename: string;
	    content_type: string;
	    size: number;
	
	    static createFrom(source: any = {}) {
	        return new Attachment(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.filename = source["filename"];
	        this.content_type = source["content_type"];
	        this.size = source["size"];
	    }
	}
	export class Message {
	    frame_number: number;
	    timestamp: string;
	    protocol: string;
	    source_ip: string;
	    source_port: number;
	    dest_ip: string;
	    dest_port: number;
	    from: string;
	    to: string;
	    subject: string;
	    date: string;
	    message_id: string;
	    body: string;
	    raw_body: string;
	    encoding: string;
	    size: number;
	    attachments: Attachment[];
	
	    static createFrom(source: any = {}) {
	        return new Message(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.frame_number = source["frame_number"];
	        this.timestamp = source["timestamp"];
	        this.protocol = source["protocol"];
	        this.source_ip = source["source_ip"];
	        this.source_port = source["source_port"];
	        this.dest_ip = source["dest_ip"];
	        this.dest_port = source["dest_port"];
	        this.from = source["from"];
	        this.to = source["to"];
	        this.subject = source["subject"];
	        this.date = source["date"];
	        this.message_id = source["message_id"];
	        this.body = source["body"];
	        this.raw_body = source["raw_body"];
	        this.encoding = source["encoding"];
	        this.size = source["size"];
	        this.attachments = this.convertValues(source["attachments"], Attachment);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace parameters {
	
	export class Parameter {
	    timestamp: string;
	    frame_num: number;
	    protocol: string;
	    type: string;
	    key: string;
	    value: string;
	    url: string;
	    method: string;
	    source_ip: string;
	    dest_ip: string;
	
	    static createFrom(source: any = {}) {
	        return new Parameter(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.frame_num = source["frame_num"];
	        this.protocol = source["protocol"];
	        this.type = source["type"];
	        this.key = source["key"];
	        this.value = source["value"];
	        this.url = source["url"];
	        this.method = source["method"];
	        this.source_ip = source["source_ip"];
	        this.dest_ip = source["dest_ip"];
	    }
	}

}

export namespace voip {
	
	export class Call {
	    id: string;
	    timestamp: string;
	    from: string;
	    to: string;
	    user_agent: string;
	    state: string;
	    src_ip: string;
	    dst_ip: string;
	    duration_sec: number;
	
	    static createFrom(source: any = {}) {
	        return new Call(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.timestamp = source["timestamp"];
	        this.from = source["from"];
	        this.to = source["to"];
	        this.user_agent = source["user_agent"];
	        this.state = source["state"];
	        this.src_ip = source["src_ip"];
	        this.dst_ip = source["dst_ip"];
	        this.duration_sec = source["duration_sec"];
	    }
	}

}

