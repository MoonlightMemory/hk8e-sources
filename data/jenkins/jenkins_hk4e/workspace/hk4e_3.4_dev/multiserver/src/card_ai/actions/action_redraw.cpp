#include <memory>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <bt/bt_node.h>
#include <common/milog/milog_stream.h>
#include <common/tools/perf/perf.h>
#include <gcg/gcg_ai_controller.h>
#include <gcg/gcg_game_mode.h>
#include <gcg/gcg_duel.h>
#include <gcg/gcg_field.h>
#include <gcg/gcg_card_zone.h>
#include <gcg/gcg_card.h>
#include <gcg/gcg_operation_base.h>
#include <gcg/gcg_operation_redraw.h>

namespace BT {

class ActionRedraw : public TreeNode {
public:
    NodeStatus tick() override {
        MiLogStream logStream;
        std::shared_ptr<Blackboard> blackboard = getBlackboard();
        if (!blackboard) {
            logStream.create(&MiLogDefault::default_log_obj_, 3u, "./src/card_ai/actions/action_redraw.cpp", "tick", 29)
                     .operator<<("ActionRedraw blackboard_ptr is nullptr, name:")
                     .operator<<(getName());
            return FAILURE;
        }

        std::shared_ptr<GCGAIController> controller;
        std::string contextKey;
        BlackboardUtil::getBlackboardGlobalKey(&contextKey, BLACK_BOARD_GLOBAL_KEY_TYPE_CONTEXT);
        if (!blackboard->get(contextKey, controller) || !controller) {
            logStream.create(&MiLogDefault::default_log_obj_, 4u, "./src/card_ai/actions/action_redraw.cpp", "tick", 37)
                     .operator<<("controller_ptr is nullptr, key:")
                     .operator<<(BlackboardUtil::resolveGlobalKey(contextKey));
            return FAILURE;
        }

        std::string reserveKey;
        std::map<unsigned int, unsigned int> curReserveMap;
        BlackboardUtil::getBlackboardGlobalKey(&reserveKey, BLACK_BORAD_GLOBAL_KEY_RESERVE_HAND_CARD_POOL);
        if (!blackboard->get(reserveKey, curReserveMap)) {
            logStream.create(&MiLogDefault::default_log_obj_, 1u, "./src/card_ai/actions/action_redraw.cpp", "tick", 51)
                     .operator<<("cur_reserve_map is empty, key:")
                     .operator<<(BlackboardUtil::resolveGlobalKey(reserveKey));
        }
        blackboard->clearAny(reserveKey);

        GCGGameMode* gameMode = controller->getGameMode();
        GCGControllerValue curControllerId = controller->getControllerId();
        GCGDuel* duel = gameMode->getDuel(curControllerId);
        GCGField* field = duel->getField(curControllerId);

        auto redrawOperation = std::make_shared<GCGOperationRedraw>();
        redrawOperation->controller_id = curControllerId;
        std::set<unsigned int>& selectCardSet = redrawOperation->select_card_set;

        if (curReserveMap.empty()) {
            GCGCardZone* handZone = field->getHandZone();
            std::vector<unsigned int> cardGuidVec;
            handZone->getCardGuidVec(cardGuidVec);
            selectCardSet.insert(cardGuidVec.begin(), cardGuidVec.end());
        } else {
            GCGCardZone* handZone = field->getHandZone();
            auto lambda = [&](GCGCard& card) {
                auto cardId = card.getId();
                if (curReserveMap[cardId] > 0) {
                    --curReserveMap[cardId];
                } else {
                    selectCardSet.insert(card.getGuid());
                }
            };
            handZone->foreachCard(lambda);
        }

        std::shared_ptr<GCGOperationBase> operationPtr = redrawOperation;
        gameMode->process(operationPtr);

        return SUCCESS;
    }
};

} // namespace BT