# NFCReaderSPM

SDK đọc dữ liệu CCCD gắn chip qua NFC trên iOS, xây dựng dựa trên chuẩn ICAO 9303.

## Cài đặt

Thêm package qua Xcode: **File → Add Package Dependencies**

```
https://github.com/DuyPham1710/NFCReaderSPM
```

## Sử dụng

### 1. Khởi tạo `NFCReader`

```swift
import NFCReaderSPM

let reader = NFCReader()
```

### 2. Tạo `MRZKey`

`MRZKey` hỗ trợ 2 cách khởi tạo:

**Cách 1 — Truyền riêng 3 trường** (số CCCD, ngày sinh, ngày hết hạn)

```swift
let mrzKey = try MRZKey(
    documentNumber: "079099012345",   // số CCCD
    dateOfBirth: "990101",             // định dạng YYMMDD
    dateOfExpiry: "300101"             // định dạng YYMMDD
)
```

**Cách 2 — Truyền thẳng 1 chuỗi MRZ đã ghép sẵn** (24 ký tự)

```swift
let mrzKey = try MRZKey(mrzKey: "0790990123458990101 6300101X4")
```

### 3. Đọc thẻ

```swift
reader.readCard(mrzKey: mrzKey) { result in
    switch result {
    case .success(let card):
        print("Đọc thành công:", card)
    case .failure(let error):
        print("Lỗi:", error.localizedDescription)
    }
}
```

### Tuỳ chỉnh thông báo hiển thị trên popup NFC

```swift
reader.readCard(
    mrzKey: mrzKey,
    customMessageHandler: { message in
        switch message {
        case .requestPresentCard:
            return "Đưa mặt sau CCCD lại gần đầu đọc phía trên iPhone"
        case .authenticatingWithCard(let progress):
            return "Đang xác thực với thẻ...\n\(progress)%"
        case .readingDataGroupProgress(let dataGroup, let progress):
            switch dataGroup {
            case .COM:
                return "Đang kiểm tra thông tin thẻ..."
            case .DG1:
                return "Đang đọc thông tin cá nhân..."
            case .DG2:
                return "Đang đọc ảnh chân dung..."
            case .DG13:
                return "Đang đọc thông tin bổ sung..."
            case .DG14:
                return "Đang xác thực bảo mật nâng cao..."
            case .SOD:
                return "Đang kiểm tra tính toàn vẹn dữ liệu..."
            }
        case .error(let error):
            return "Có lỗi xảy ra: \(error.localizedDescription)\nVui lòng thử lại."
        case .successfulRead:
            return "Đã đọc xong!"
        }
    },
    completed: { result in
        switch result {
        case .success(let card):
            print("Đọc thành công:", card)
            scanned = card
        case .failure(let error):
            print("Lỗi:", error.localizedDescription)
        }
    }
)
```
