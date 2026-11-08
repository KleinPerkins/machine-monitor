import Foundation
@main struct Harness {
    static func main() {
        var model = RecoveryPresentation()
        precondition(!model.canRestore && !model.canLaunch)
        model.targetPath = "/fixture/Monitor.app"
        model.begin(); precondition(model.busy && !model.canRestore)
        model.consume(["ok":true,"can_restore":true,"transaction_id":"fixture","previous_version":"1.0","message":"Ready"])
        precondition(!model.busy && model.canRestore && !model.canLaunch)
        precondition(model.message.contains("1.0") && model.message.contains("retained"))
        model.begin(); precondition(!model.canRestore)
        model.consume(["ok":false,"error":"Restart your Mac"])
        precondition(!model.canRestore && !model.canLaunch && model.message == "Restart your Mac")
        model.consume(["ok":true,"phase":"accepted","restored":["build":1],"message":"Restored"])
        precondition(model.canLaunch && !model.canRestore)
        model.consume(["ok":true,"phase":"accepted"])
        precondition(!model.canLaunch)
        print("Recovery presentation: 8 assertions passed")
    }
}
